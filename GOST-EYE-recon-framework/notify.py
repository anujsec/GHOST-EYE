"""
notify.py — push meaningful deltas to Slack / Discord / Telegram.

Kept dependency-free (urllib only) so the framework doesn't force a
`requests` install just for this. If you'd rather use `notify`
(projectdiscovery's tool), swap send() to shell out to it instead.
"""

import json
import logging
import urllib.request

log = logging.getLogger("recon.notify")


def _post_json(url: str, payload: dict):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:
        log.warning("notification failed: %s", e)


def send(cfg: dict, text: str):
    if not text or not text.strip():
        return
    cfg = cfg or {}
    slack_url = cfg.get("slack_webhook")
    discord_url = cfg.get("discord_webhook")
    telegram_token = cfg.get("telegram_bot_token")
    telegram_chat_id = cfg.get("telegram_chat_id")

    if slack_url:
        _post_json(slack_url, {"text": text})
    if discord_url:
        # Discord caps message content at 2000 chars
        _post_json(discord_url, {"content": text[:1990]})
    if telegram_token and telegram_chat_id:
        url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
        _post_json(url, {"chat_id": telegram_chat_id, "text": text[:4000]})

    if not any([slack_url, discord_url, telegram_token]):
        log.debug("[no webhook configured] %s", text)


def format_diff_message(org: str, layer: str, table: str, diff: dict) -> str:
    lines = [f"*[{org}] {layer} — {table} changes*"]
    if diff["new"]:
        lines.append(f"🟢 {len(diff['new'])} new:")
        for k, _ in diff["new"][:20]:
            lines.append(f"  + {k}")
        if len(diff["new"]) > 20:
            lines.append(f"  ...and {len(diff['new']) - 20} more")
    if diff["changed"]:
        lines.append(f"🟡 {len(diff['changed'])} changed:")
        for k, _, _ in diff["changed"][:10]:
            lines.append(f"  ~ {k}")
    if diff["removed"]:
        lines.append(f"🔴 {len(diff['removed'])} removed/inactive:")
        for k, _ in diff["removed"][:10]:
            lines.append(f"  - {k}")
    if len(lines) == 1:
        return ""  # nothing changed, don't spam
    return "\n".join(lines)
