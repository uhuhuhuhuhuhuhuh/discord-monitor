from app.detection import evaluate_content

CFG = {
    "monitor": {"alert_threshold": 35},
    "rules": {
        "suspicious_tlds": ["tk", "ml", "ga"],
        "suspicious_domain_keywords": ["gift", "nitro"],
        "suspicious_phrases": ["verify your account", "claim now"],
        "url_shorteners": ["bit.ly"],
        "risky_extensions": ["exe", "scr", "js"],
        "brand_keywords": ["discord", "steam"],
        "allow_domains": ["discord.com"],
        "deny_domains": [],
    },
    "scoring": {
        "suspicious_tld": 20,
        "domain_keyword": 12,
        "social_engineering_phrase": 25,
        "shortener": 12,
        "ip_url": 20,
        "punycode": 25,
        "url_userinfo": 25,
        "unusual_port": 15,
        "brand_impersonation": 35,
        "denylisted_domain": 80,
        "risky_attachment": 40,
        "double_extension": 35,
        "secret_leak": 60,
        "qr_url": 15,
        "outgoing_multiplier": 1.35,
    },
}


def test_suspicious_url_and_phrase():
    result = evaluate_content("Verify your account https://discord-nitro-gift.tk/login", CFG)
    assert result.suspicious
    assert result.score >= 35
    assert "discord-nitro-gift.tk" in result.domains


def test_allowlisted_domain():
    result = evaluate_content("https://discord.com/channels/1/2", CFG)
    assert not result.suspicious


def test_risky_attachment():
    result = evaluate_content("here", CFG, attachment_names=["photo.png.exe"])
    assert result.suspicious
    assert any(reason.code == "double_extension" for reason in result.reasons)


def test_secret_is_redacted():
    result = evaluate_content("api_key=abcdefghijklmnopqrstuvwxyz123456", CFG)
    assert "[REDACTED:generic_api_key]" in result.redacted_text
    assert result.suspicious
