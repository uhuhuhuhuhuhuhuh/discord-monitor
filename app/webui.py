from __future__ import annotations

import csv
import io
from typing import Any

from aiohttp import web

from .config import load_settings
from .db import Database


def build_app(db: Any, config: dict) -> web.Application:
    app = web.Application()

    async def index(request: web.Request) -> web.Response:
        return web.Response(text='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Discord Monitor</title><style>body{font-family:system-ui;background:#111318;color:#e9edf4;margin:0}main{max-width:1050px;margin:auto;padding:24px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,table{background:#1b1f27;border:1px solid #303744;border-radius:10px}.card{padding:16px}.n{font-size:2rem;font-weight:700}table{width:100%;border-collapse:collapse;margin-top:18px}th,td{padding:9px;border-bottom:1px solid #303744;text-align:left;font-size:.9rem}.muted{color:#9ea8b7}</style></head><body><main><h1>Discord Monitor</h1><p class="muted">Local security dashboard</p><div class="cards" id="cards"></div><p><a href="/api/export/events.json">Export JSON</a> · <a href="/api/export/events.csv">Export CSV</a></p><table><thead><tr><th>Time</th><th>Severity</th><th>Direction</th><th>Summary</th><th>Score</th></tr></thead><tbody id="events"></tbody></table><script>async function r(){let s=await fetch('/api/stats').then(x=>x.json());cards.innerHTML=Object.entries(s).map(([k,v])=>`<div class=card><div class=n>${v}</div><div class=muted>${k}</div></div>`).join('');let e=await fetch('/api/events?limit=100').then(x=>x.json());events.innerHTML=e.map(x=>`<tr><td>${x.created_at}</td><td>${x.severity}</td><td>${x.direction||''}</td><td>${x.summary||''}</td><td>${x.score}</td></tr>`).join('')}r();setInterval(r,10000)</script></main></body></html>''', content_type="text/html")

    async def health(request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    async def stats(request: web.Request) -> web.Response:
        return web.json_response(db.stats())

    async def events(request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", "100"))
        return web.json_response(db.recent_events(limit))

    async def current_config(request: web.Request) -> web.Response:
        return web.json_response(config)

    async def export_json(request: web.Request) -> web.Response:
        return web.json_response(db.recent_events(1000), headers={"Content-Disposition": "attachment; filename=events.json"})

    async def export_csv(request: web.Request) -> web.Response:
        rows = db.recent_events(1000)
        out = io.StringIO()
        fields = list(rows[0].keys()) if rows else ["id", "created_at", "event_type", "severity", "score"]
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
        return web.Response(text=out.getvalue(), content_type="text/csv", headers={"Content-Disposition": "attachment; filename=events.csv"})

    app.add_routes([
        web.get("/", index),
        web.get("/health", health),
        web.get("/api/stats", stats),
        web.get("/api/events", events),
        web.get("/api/config", current_config),
        web.get("/api/export/events.json", export_json),
        web.get("/api/export/events.csv", export_csv),
    ])
    return app


def main() -> None:
    settings = load_settings(require_discord=False)
    db = Database(settings.db_path)
    web.run_app(build_app(db, settings.raw), host=settings.web_host, port=settings.web_port, print=None)


if __name__ == "__main__":
    main()
