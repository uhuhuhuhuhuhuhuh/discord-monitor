from __future__ import annotations

import base64
from dataclasses import dataclass

import aiohttp


@dataclass(slots=True)
class URLReputation:
    url: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    source: str = "virustotal"
    available: bool = False


def virustotal_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


async def lookup_virustotal(url: str, api_key: str, session: aiohttp.ClientSession | None = None) -> URLReputation:
    report = URLReputation(url=url)
    owns_session = session is None
    if owns_session:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
    assert session is not None
    try:
        url_id = virustotal_url_id(url)
        async with session.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key, "accept": "application/json"},
        ) as response:
            if response.status != 200:
                return report
            payload = await response.json()
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            report.malicious = int(stats.get("malicious", 0) or 0)
            report.suspicious = int(stats.get("suspicious", 0) or 0)
            report.harmless = int(stats.get("harmless", 0) or 0)
            report.undetected = int(stats.get("undetected", 0) or 0)
            report.available = True
            return report
    except (aiohttp.ClientError, TimeoutError, ValueError, TypeError):
        return report
    finally:
        if owns_session:
            await session.close()


async def lookup_many_virustotal(urls: list[str], api_key: str, max_urls: int = 3) -> list[URLReputation]:
    selected = list(dict.fromkeys(urls))[:max(1, min(max_urls, 10))]
    if not selected:
        return []
    timeout = aiohttp.ClientTimeout(total=12)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        results = []
        for url in selected:
            results.append(await lookup_virustotal(url, api_key, session))
        return results
