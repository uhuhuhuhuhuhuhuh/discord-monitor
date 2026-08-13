# Discord Monitor

Python/Docker monitor using `discord.py-self` that logs message and guild-join events, evaluates message content for suspicious URLs/social-engineering phrases, and sends alerts to a configured Discord channel.

> `discord.py-self` automates a Discord user account. Discord may prohibit this under its Terms of Service and may take action against accounts using self-bots.

## Files

```text
discord-monitor/
├── monitor.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── .dockerignore
└── logs/
```

## Ubuntu setup

```bash
git clone https://github.com/uhuhuhuhuhuhuhuh/discord-monitor.git
cd discord-monitor
cp .env.example .env
nano .env
```

Set:

```env
DISCORD_TOKEN=your_real_token_here
DISCORD_TARGET_CHANNEL_ID=123456789012345678
```

Then:

```bash
chmod 600 .env
mkdir -p logs
docker compose up -d --build
```

Check status and logs:

```bash
docker compose ps
docker compose logs -f discord-monitor
```

Persistent file log:

```bash
tail -f logs/discord_monitor.log
```

## Update

```bash
git pull --ff-only
docker compose up -d --build
```

Never commit your real `.env` file or Discord token.
