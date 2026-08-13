# Discord Monitor

A small Python monitor built with `discord.py-self` that watches Discord message and guild-join events, evaluates message text for suspicious URLs and social-engineering phrases, and sends JSON-formatted alerts to a configured Discord channel.

> **Important:** `discord.py-self` uses a Discord user session token. Using self-bot/user-token automation may violate Discord's Terms of Service and can result in account action. Use only on an account you control and understand the risk.

## Features

- Loads configuration from environment variables
- Logs to stdout and `/app/logs/discord_monitor.log`
- Watches message events
- Watches guild join events
- Extracts URLs from message text
- Flags suspicious TLDs and domain keywords
- Flags common social-engineering phrases
- Sends JSON alert messages to a configured channel
- Dockerized for simple deployment on Ubuntu/Linux
- Restarts automatically with Docker Compose

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
└── README.md
```

## Ubuntu deployment

Install Git and Docker if needed, then clone the repository:

```bash
git clone https://github.com/uhuhuhuhuhuhuhuh/discord-monitor.git
cd discord-monitor
```

Create your local environment file:

```bash
cp .env.example .env
nano .env
```

Set:

```env
DISCORD_TOKEN=your_real_token_here
DISCORD_TARGET_CHANNEL_ID=123456789012345678
```

Protect it:

```bash
chmod 600 .env
```

Start the service:

```bash
docker compose up -d --build
```

Check status:

```bash
docker compose ps
```

Watch logs:

```bash
docker compose logs -f discord-monitor
```

Persistent logs are stored under:

```text
./logs/discord_monitor.log
```

## Updating

After changes are pushed to GitHub:

```bash
git pull --ff-only
docker compose up -d --build
```

## Environment variables

| Variable | Required | Purpose |
|---|---:|---|
| `DISCORD_TOKEN` | Yes | Discord session token |
| `DISCORD_TARGET_CHANNEL_ID` | Yes | Channel used for alert messages |

Never commit your real `.env` file or token to GitHub.
