#!/usr/bin/env python3
"""
M0 backing monitor -> Telegram.  On-chain only (no M0 API).

Reads the M0 MinterGateway contract on Ethereum mainnet through a JSON-RPC
endpoint: total $M owed (totalOwedM) vs. the collateral each minter has
reported on-chain, and:
  * answers /backing and /minters in Telegram on demand
  * posts a summary to TG_CHAT_ID at REPORT_HOURS (local REPORT_TZ time)
  * alerts when collateralisation drops below ALERT_RATIO, when a minter's
    collateral report has expired (the contract then counts it as $0) or is
    about to expire, and when a new minter is activated

Note: "collateral" is the value each minter reports on-chain (signed by M0
validators). The real-world reserves (T-bills/cash) are off-chain.

Configuration comes from environment variables (see m0bot.env.example; under
systemd they are loaded with EnvironmentFile=).

Env vars (required):  TG_BOT_TOKEN
                      TG_CHAT_ID         chat/channel for scheduled posts + alerts
                                         (optional when running continuously:
                                         without it the bot only answers commands)
Env vars (optional):  RPC_URL            default: contents of ~/.m0bot_rpc,
                                         else https://ethereum-rpc.publicnode.com
                      ALERT_RATIO        default 1.00  (100%)
                      EXPIRY_WARN_HOURS  default 6
                      REPORT_HOURS       default "8,16,24"  (24 = midnight)
                      REPORT_TZ          default Europe/Prague (CET/CEST)
                      CHECK_MINUTES      default 60
                      MINTER_LABELS      extra/override names, e.g. "0xabc...=Name"
                      EXTRA_MINTERS      extra minter addresses, comma separated
                      STATE_FILE         where sent alerts / last report / found
                                         minters are kept across restarts; default
                                         $STATE_DIRECTORY/m0bot_state.json (set by
                                         systemd StateDirectory=), else ~/.m0bot_state.json

Run continuously:  python m0_backing_bot.py
One-shot (cron):   python m0_backing_bot.py --once     (sends summary to TG_CHAT_ID)
Print only:        python m0_backing_bot.py --print
"""
import os
import sys
import json
import time
import html
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")  # journald adds timestamps
log = logging.getLogger("m0bot")


def _rpc_url() -> str:
    """RPC_URL env var, else ~/.m0bot_rpc, else a public node."""
    if os.environ.get("RPC_URL"):
        return os.environ["RPC_URL"]
    try:
        with open(os.path.expanduser("~/.m0bot_rpc")) as f:
            return f.read().strip()
    except OSError:
        return "https://ethereum-rpc.publicnode.com"


def _state_file() -> str:
    if os.environ.get("STATE_FILE"):
        return os.path.expanduser(os.environ["STATE_FILE"])
    if os.environ.get("STATE_DIRECTORY"):  # set by systemd StateDirectory=
        return os.path.join(os.environ["STATE_DIRECTORY"].split(":")[0], "m0bot_state.json")
    return os.path.expanduser("~/.m0bot_state.json")


RPC_URL = _rpc_url()
MINTER_GATEWAY = "0xf7f9638cb444D65e5A40bF5ff98ebE4ff319F04E"
EXPLORER = "https://etherscan.io/address/"
DECIMALS = 6  # $M and collateral values are 6-decimal integers

# 4-byte selectors of the MinterGateway view functions we read
SEL = {
    "totalOwedM": "0xf962a44b",
    "collateralOf": "0x1aefb107",
    "activeOwedMOf": "0x4be1c1cd",
    "inactiveOwedMOf": "0xaf9979c9",
    "collateralUpdateTimestampOf": "0x7efb685b",
    "collateralExpiryTimestampOf": "0x7572840e",
    "isActiveMinter": "0xa8c01961",
    "isFrozenMinter": "0xe806250a",
}
# MinterActivated(address indexed minter, address indexed caller)
TOPIC_MINTER_ACTIVATED = "0x2531adeb71f8681e6f4644f88cb102c71370151986071c92d43a7e82d217462a"
LOG_CHUNK = 1000  # free RPCs only serve logs for recent blocks in small ranges
GATEWAY_FROM_BLOCK = 19_800_000  # just before the MinterGateway was deployed
TG_MAX_LEN = 4000  # Telegram limit is 4096 chars per message

# Fallback list. With an archive RPC (e.g. Alchemy) all minters are also
# discovered from the full event history at startup; new ones are picked up
# by watching new blocks while running.
KNOWN_MINTERS = [
    "0x7f7489582b64abe46c074a45d758d701c2ca5446",
    "0xcd1394d24e1e404f9eb3609f872b0736becb9d74",
    "0x5d238f4eac94da0a635ee39fa389a4754395d5d9",
    "0x1d5b695d13f231a605d231631c688fb33477b249",
    "0x6768cda9f017c82074ea9f646621d80da8ff5f7f",
]

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
STATE_FILE = _state_file()
ALERT_RATIO = float(os.environ.get("ALERT_RATIO", "1.00"))
EXPIRY_WARN_HOURS = float(os.environ.get("EXPIRY_WARN_HOURS", "6"))
REPORT_TZ = ZoneInfo(os.environ.get("REPORT_TZ", "Europe/Prague"))
REPORT_HOURS = {int(h) % 24 for h in os.environ.get("REPORT_HOURS", "8,16,24").split(",")}
CHECK_MINUTES = int(os.environ.get("CHECK_MINUTES", "60"))
LABELS = {
    "0x7f7489582b64abe46c074a45d758d701c2ca5446": "MXON",
    "0xcd1394d24e1e404f9eb3609f872b0736becb9d74": "Bridge",
    "0x5d238f4eac94da0a635ee39fa389a4754395d5d9": "MoonPay",
    "0x1d5b695d13f231a605d231631c688fb33477b249": "1Money",
    **{
        k.strip().lower(): v.strip()
        for k, v in (p.split("=", 1) for p in os.environ.get("MINTER_LABELS", "").split(",") if "=" in p)
    },
}
MINTERS = list(dict.fromkeys(
    KNOWN_MINTERS + [a.strip().lower() for a in os.environ.get("EXTRA_MINTERS", "").split(",") if a.strip()]
))


# ----------------------------------------------------------------- rpc ----
def rpc_batch(calls: list[tuple[str, list]]) -> list:
    payload = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]
    r = requests.post(RPC_URL, json=payload, timeout=30)
    r.raise_for_status()
    res = sorted(r.json(), key=lambda x: x["id"])
    for x in res:
        if "error" in x:
            raise RuntimeError(f"RPC error: {x['error']}")
    return [x["result"] for x in res]


def rpc(method: str, params: list):
    return rpc_batch([(method, params)])[0]


def eth_call(fn: str, block: str, addr: str | None = None) -> tuple[str, list]:
    data = SEL[fn] + (addr[2:].lower().rjust(64, "0") if addr else "")
    return ("eth_call", [{"to": MINTER_GATEWAY, "data": data}, block])


def scan_new_minters(from_block: int, to_block: int) -> list[str]:
    found = []
    for start in range(from_block, to_block + 1, LOG_CHUNK):
        logs = rpc("eth_getLogs", [{
            "address": MINTER_GATEWAY,
            "fromBlock": hex(start),
            "toBlock": hex(min(start + LOG_CHUNK - 1, to_block)),
            "topics": [TOPIC_MINTER_ACTIVATED],
        }])
        found += ["0x" + log["topics"][1][-40:].lower() for log in logs]
    return [a for a in dict.fromkeys(found) if a not in MINTERS]


def discover_all_minters():
    """Adds every minter ever activated. Needs an archive RPC; public nodes refuse the full range."""
    try:
        logs = rpc("eth_getLogs", [{
            "address": MINTER_GATEWAY,
            "fromBlock": hex(GATEWAY_FROM_BLOCK),
            "toBlock": "latest",
            "topics": [TOPIC_MINTER_ACTIVATED],
        }])
    except Exception as e:
        log.warning("full minter scan unavailable, using known list: %s", e)
        return
    for a in dict.fromkeys("0x" + log["topics"][1][-40:].lower() for log in logs):
        if a not in MINTERS:
            MINTERS.append(a)


# ---------------------------------------------------------------- data ----
PER_MINTER = ["collateralOf", "activeOwedMOf", "inactiveOwedMOf", "collateralUpdateTimestampOf",
              "collateralExpiryTimestampOf", "isActiveMinter", "isFrozenMinter"]


def fetch() -> dict:
    """All reads are pinned to one block so the numbers are consistent."""
    block = rpc("eth_blockNumber", [])
    calls = [("eth_getBlockByNumber", [block, False]), eth_call("totalOwedM", block)]
    for m in MINTERS:
        calls += [eth_call(fn, block, m) for fn in PER_MINTER]
    res = rpc_batch(calls)
    raw = {"block": int(block, 16), "block_ts": int(res[0]["timestamp"], 16), "totalOwedM": int(res[1], 16)}
    raw["minters"] = {
        m: dict(zip(PER_MINTER, (int(v, 16) for v in res[2 + i * len(PER_MINTER): 2 + (i + 1) * len(PER_MINTER)])))
        for i, m in enumerate(MINTERS)
    }
    return raw


def units(raw: int) -> float:
    return raw / 10**DECIMALS


def short(addr: str) -> str:
    return addr[:6] + "…" + addr[-4:]


def parse(raw: dict) -> dict:
    now = raw["block_ts"]
    minters = []
    for addr, v in raw["minters"].items():
        coll = units(v["collateralOf"])
        owed = units(v["activeOwedMOf"] + v["inactiveOwedMOf"])
        expiry = v["collateralExpiryTimestampOf"]
        minters.append({
            "address": addr,
            "label": LABELS.get(addr, short(addr)),
            "active": bool(v["isActiveMinter"]),
            "frozen": bool(v["isFrozenMinter"]),
            "collateral": coll,
            "owed": owed,
            "ratio": coll / owed if owed > 0 else None,
            "update_ts": v["collateralUpdateTimestampOf"],
            "expiry_ts": expiry,
            "expired": owed > 0 and now >= expiry,
            "expiring": owed > 0 and 0 < expiry - now < EXPIRY_WARN_HOURS * 3600,
        })
    minters.sort(key=lambda x: x["owed"], reverse=True)
    s = units(raw["totalOwedM"])
    c = sum(m["collateral"] for m in minters if m["active"])
    return {
        "supply": s,
        "collateral": c,
        "ratio": c / s if s else None,
        "block": raw["block"],
        "block_ts": raw["block_ts"],
        "minters": minters,
    }


# ------------------------------------------------------------ formatting --
def money(x: float) -> str:
    sign, x = ("-" if x < 0 else ""), abs(x)
    if x >= 1e9:
        return f"{sign}${x/1e9:,.3f}B"
    if x >= 1e6:
        return f"{sign}${x/1e6:,.2f}M"
    return f"{sign}${x:,.0f}"


def hours(seconds: float) -> str:
    h = seconds / 3600
    return f"{h*60:.0f} min" if h < 1 else f"{h:.1f} h"


def fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def link(m: dict) -> str:
    return f'<a href="{EXPLORER}{m["address"]}">{html.escape(m["label"])}</a>'


def pct(r) -> str:
    return f"{r*100:.1f}%" if r is not None else "n/a"


def minter_flag(m: dict) -> str:
    if m["expired"] or m["frozen"]:
        return "⛔"
    if m["expiring"] or (m["ratio"] is not None and m["ratio"] < ALERT_RATIO):
        return "⚠️"
    return "🟢"


def minter_note(m: dict, now: int) -> str:
    if m["expired"]:
        return f"collateral report EXPIRED {hours(now - m['expiry_ts'])} ago"
    note = f"updated {hours(now - m['update_ts'])} ago"
    if m["expiring"]:
        note += f", expires in {hours(m['expiry_ts'] - now)}"
    if m["frozen"]:
        note += ", FROZEN"
    return note


def summary(d: dict) -> str:
    ratio = d["ratio"]
    flag = "🟢" if ratio and ratio >= ALERT_RATIO else "🔴"
    active = [m for m in d["minters"] if m["active"]]
    lines = [
        "<b>M0 backing</b> (on-chain)",
        f"{flag} Collateralisation: <b>{pct(ratio)}</b>",
        f"Collateral: <b>{money(d['collateral'])}</b>",
        f"$M owed:    <b>{money(d['supply'])}</b>",
        f"Buffer:     {money(d['collateral'] - d['supply'])}",
        f"Active minters: {len(active)}",
        f"Block {d['block']:,} ({fmt_ts(d['block_ts'])})",
    ]
    if active:
        lines.append("")
        lines.append("<b>By minter</b> (collateral / owed)")
        for m in active[:10]:
            lines.append(
                f"{minter_flag(m)} {link(m)}: {money(m['collateral'])} / {money(m['owed'])}  ({pct(m['ratio'])})\n"
                f"     <i>{minter_note(m, d['block_ts'])}</i>"
            )
    return "\n".join(lines)


def minters_detail(d: dict) -> str:
    lines = [f"<b>All minters</b> (block {d['block']:,})"]
    for m in d["minters"]:
        status = ("active" if m["active"] else "inactive") + (", frozen" if m["frozen"] else "")
        lines.append(
            f"{minter_flag(m)} <b>{link(m)}</b> ({status})\n"
            f"  <code>{m['address']}</code>\n"
            f"  collateral {money(m['collateral'])} | owed {money(m['owed'])} | {pct(m['ratio'])}\n"
            f"  last update {fmt_ts(m['update_ts'])} | expiry {fmt_ts(m['expiry_ts'])}"
        )
    return "\n\n".join(lines)  # blank line between minters


def alerts(d: dict) -> dict[str, str]:
    """Returns {stable key: message}; the key is used to avoid repeating an alert every check."""
    out = {}
    if d["ratio"] is not None and d["ratio"] < ALERT_RATIO:
        out["ratio"] = f"🚨 M0 collateralisation {pct(d['ratio'])} is below {ALERT_RATIO*100:.0f}%"
    now = d["block_ts"]
    for m in d["minters"]:
        a = m["address"]
        if m["expired"]:
            out[f"expired:{a}"] = (
                f"⛔ {link(m)} collateral report expired {hours(now - m['expiry_ts'])} ago "
                f"(last update {fmt_ts(m['update_ts'])}). The contract now counts its collateral as $0 "
                f"against {money(m['owed'])} owed."
            )
        elif m["expiring"]:
            out[f"expiring:{a}"] = f"⚠️ {link(m)} collateral report expires in {hours(m['expiry_ts'] - now)}"
        elif m["active"] and m["ratio"] is not None and m["ratio"] < ALERT_RATIO:
            out[f"under:{a}"] = (
                f"⚠️ {link(m)} collateralisation {pct(m['ratio'])}: "
                f"{money(m['collateral'])} / {money(m['owed'])}"
            )
        if m["frozen"]:
            out[f"frozen:{a}"] = f"🧊 {link(m)} is frozen"
    return out


# ----------------------------------------------------------------- state --
def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state: dict):
    """Atomic write so a crash mid-write can't leave a corrupt file."""
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_FILE)
    except OSError as e:
        log.warning("could not save state to %s: %s", STATE_FILE, e)


# -------------------------------------------------------------- telegram --
def tg(method: str, **params):
    r = requests.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/{method}", json=params, timeout=40)
    r.raise_for_status()
    return r.json()


def send(chat_id, text: str):
    """Splits on blank lines so long messages stay under Telegram's limit without breaking HTML tags."""
    chunks, cur = [], ""
    for part in text.split("\n\n"):
        if cur and len(cur) + len(part) + 2 > TG_MAX_LEN:
            chunks.append(cur)
            cur = part
        else:
            cur = f"{cur}\n\n{part}" if cur else part
    chunks.append(cur)
    for c in chunks:
        tg("sendMessage", chat_id=chat_id, text=c, parse_mode="HTML", disable_web_page_preview=True)


def handle(update: dict):
    msg = update.get("message") or update.get("channel_post")
    if not msg or "text" not in msg:
        return
    chat_id = msg["chat"]["id"]
    cmd = msg["text"].split()[0].split("@")[0].lower()
    try:
        if cmd in ("/start", "/help"):
            send(chat_id, f"Commands: /backing, /minters\nThis chat id: <code>{chat_id}</code>")
        elif cmd == "/backing":
            send(chat_id, summary(parse(fetch())))
        elif cmd == "/minters":
            send(chat_id, minters_detail(parse(fetch())))
    except Exception as e:  # keep the bot alive on RPC hiccups
        send(chat_id, f"Error reading M0 on-chain data: {html.escape(str(e))[:500]}")


def run_forever():
    state = load_state()
    for a in state.get("minters", []):  # minters found by block scans in earlier runs
        if a not in MINTERS:
            MINTERS.append(a)
    offset, last_check = None, 0.0
    last_report = state.get("last_report")          # "YYYY-MM-DDTHH" of the last scheduled post
    last_alert = set(state.get("alerts", []))       # alert keys already sent
    last_scanned = state.get("last_scanned")        # last block scanned for new minters

    def save():
        save_state({"last_report": last_report, "alerts": sorted(last_alert),
                    "last_scanned": last_scanned, "minters": MINTERS})

    log.info("Bot running (%d minters, state %s). Send /start to it in Telegram to get a chat id.",
             len(MINTERS), STATE_FILE)
    if not TG_CHAT_ID:
        log.warning("TG_CHAT_ID not set: answering commands only, no scheduled posts or alerts")
    while True:
        try:
            res = tg("getUpdates", offset=offset, timeout=30)
            for u in res.get("result", []):
                offset = u["update_id"] + 1
                handle(u)
        except Exception as e:
            log.warning("telegram poll error: %s", e)
            time.sleep(5)

        if not TG_CHAT_ID:
            continue

        # scheduled report: checked every poll (~30 s) so a slot is never skipped
        now = datetime.now(REPORT_TZ)
        slot = now.strftime("%Y-%m-%dT%H")
        if now.hour in REPORT_HOURS and last_report != slot:
            try:
                send(TG_CHAT_ID, summary(parse(fetch())))
                last_report = slot
                save()
            except Exception as e:
                log.warning("report error: %s", e)

        if time.time() - last_check < CHECK_MINUTES * 60:
            continue
        last_check = time.time()

        # minter scan and alert check fail independently, so a refused eth_getLogs can't block alerts
        try:
            head = int(rpc("eth_blockNumber", []), 16)
            if last_scanned is None:
                last_scanned = head
            for a in scan_new_minters(last_scanned + 1, head):
                MINTERS.append(a)
                send(TG_CHAT_ID, f'🆕 New M0 minter activated: <a href="{EXPLORER}{a}">{short(a)}</a>')
            last_scanned = head
        except Exception as e:
            log.warning("minter scan error: %s", e)

        try:
            current = alerts(parse(fetch()))
            for key in current.keys() - last_alert:  # only send new alerts, not repeats
                send(TG_CHAT_ID, current[key])
            last_alert = set(current)
        except Exception as e:
            log.warning("alert check error: %s", e)
        save()


if __name__ == "__main__":
    if "--print" not in sys.argv and not TG_BOT_TOKEN:
        sys.exit("Set TG_BOT_TOKEN (create a bot with @BotFather)")
    if "--once" in sys.argv and not TG_CHAT_ID:
        sys.exit("Set TG_CHAT_ID")
    discover_all_minters()
    if "--print" in sys.argv:
        d = parse(fetch())
        print(summary(d))
        print()
        print("\n".join(alerts(d).values()))
    elif "--once" in sys.argv:
        d = parse(fetch())
        send(TG_CHAT_ID, summary(d))
        for a in alerts(d).values():
            send(TG_CHAT_ID, a)
    else:
        run_forever()
