# M0 backing bot

Requires Python 3.9 or newer. Set up the virtual environment and local config once from the clone.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
[ -f .env ] || (umask 077; cp .env.example .env)
```

Fill in `TG_BOT_TOKEN` in `.env`. Set `TG_CHAT_ID` for scheduled reports and alerts.
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
