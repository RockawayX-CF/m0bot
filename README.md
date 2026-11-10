# M0 backing bot

Requires Python 3.9 or newer. Set up the virtual environment and local config once from the clone.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
[ -f .env ] || (umask 077; cp .env.example .env)
```

Fill in `SCRIPT_OWNER` and `TG_BOT_TOKEN` in `.env`. Set `TG_CHAT_ID` for scheduled reports and alerts.
If you already have a local `m0bot.env`, copy its values into `.env`.

Activate the virtual environment and start the bot in the attached `screen` session.

```sh
. .venv/bin/activate
python3 m0_backing_bot.py
```

Press **Ctrl+A, then D** to detach. The bot loads `.env` from the script's directory,
and existing environment variables take precedence. The systemd unit still reads
`/etc/m0bot.env` and uses `/opt/m0bot/venv`. Install the requirements into that
virtual environment when updating a systemd deployment.

## Logging

This uses the UnderQuant logger from `underquant_agent/agent_controller/logger_utils.py`.
The repository and service are `m0bot`, and the runtime is `backing_bot`.
Set `SCRIPT_OWNER` to the lower-case person or team responsible for the deployment.
For local runs, the default is the UnderQuant human-readable console on stderr.

For the `honza` screen deployment on `traderplayground`, set these in `.env`:

```dotenv
LOG_MODE=jsonl
LOG_INSTANCE=playground
LOG_CONSOLE=true
```

Use a distinct `LOG_INSTANCE` for each concurrent bot and a screen name such as
`m0bot_playground`. Alloy matches
`/var/log/trading/honza/m0bot/backing_bot/playground/<run_id>.<segment>.jsonl`.
For systemd, put `SCRIPT_OWNER` in `/etc/m0bot.env` and use journal mode with the
unit identifier `m0bot.backing_bot.main`.

Events include the PID, run ID, and screen name when available. Backing checks
log at `CHECK_MINUTES` intervals, or the bot logs an hourly heartbeat in
commands-only mode. Telegram polling failures and RPC failures include a safe
error type and HTTP status when available. The bot’s JSON state file remains
the source for report and alert deduplication.
