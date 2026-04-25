#!/usr/bin/env python3
"""
Wazuh → n8n Integration Script (Full Raw Alert Edition)
========================================================
File: /var/ossec/integrations/custom-n8n.py
Version: 4.0 — Fixed alert reading for Wazuh 4.x

CHANGELOG v4.0:
  - FIXED read_alert() — Wazuh 4.x does NOT use stdin.
    It writes the alert JSON to a temp file in /tmp/ and
    passes the file path as sys.argv[1].
    Script now reads from argv[1] file first, falls back
    to stdin only for manual testing.
  - Everything else is identical to v3.0.
"""

import sys
import os
import json
import urllib.request
import urllib.error
import logging
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────
FALLBACK_WEBHOOK_URL = "http://192.168.0.168:5678/webhook/wazuh-alerts"
REQUEST_TIMEOUT      = 15
LOG_FILE             = "/var/ossec/logs/integrations/n8n.log"
# ─────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════
# SETUP
# ══════════════════════════════════════════════════════════════════════

def setup_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def get_webhook_url():
    if len(sys.argv) >= 4 and sys.argv[3].startswith("http"):
        url = sys.argv[3]
        logging.info(f"hook_url from argv[3]: {url}")
        return url
    logging.warning(f"No argv[3] found — using fallback: {FALLBACK_WEBHOOK_URL}")
    return FALLBACK_WEBHOOK_URL


def get_pipeline_name(webhook_url):
    try:
        return webhook_url.rstrip("/").split("/")[-1] or "wazuh-unknown"
    except Exception:
        return "wazuh-unknown"


# ══════════════════════════════════════════════════════════════════════
# ALERT READING — FIXED FOR WAZUH 4.x
# ══════════════════════════════════════════════════════════════════════

def read_alert():
    """
    HOW WAZUH 4.x PASSES ALERT DATA:

    Wazuh integratord writes the full alert JSON to a temporary
    file in /tmp/ named like:
        custom-n8n-1773126775-123456789.alert

    It then passes that file path as sys.argv[1] to this script.

    Reading sys.stdin in Wazuh 4.x returns EMPTY because Wazuh
    never writes to stdin — it uses the temp file in /tmp/.

    Priority order:
      1. argv[1] file path  → Wazuh 4.x production (primary)
      2. stdin              → manual testing fallback
    """
    raw = None

    # ── Method 1: Read from argv[1] file (Wazuh 4.x) ─────────────────
    if len(sys.argv) >= 2 and sys.argv[1] not in ("", "test_alert_file"):
        alert_file = sys.argv[1]
        if os.path.isfile(alert_file):
            try:
                with open(alert_file, 'r', encoding='utf-8') as f:
                    raw = f.read()
                logging.info(f"Alert read from file: {alert_file}")
            except Exception as e:
                logging.warning(f"Could not read alert file {alert_file}: {e}")
                raw = None
        else:
            logging.warning(f"argv[1] is not a valid file: {alert_file}")

    # ── Method 2: Fall back to stdin (manual testing) ─────────────────
    if not raw or not raw.strip():
        try:
            raw = sys.stdin.read()
            if raw and raw.strip():
                logging.info("Alert read from stdin (manual test mode)")
        except Exception as e:
            logging.error(f"Stdin read error: {e}")
            raw = None

    # ── Final check ───────────────────────────────────────────────────
    if not raw or not raw.strip():
        logging.error(
            "No alert data from argv[1] file or stdin. "
            f"argv={sys.argv}"
        )
        sys.exit(1)

    # ── Parse JSON ────────────────────────────────────────────────────
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logging.error(f"Alert JSON parse failed: {e} | preview: {raw[:200]}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════
# PAYLOAD BUILDER
# ══════════════════════════════════════════════════════════════════════

def severity_label(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if level >= 15: return "CRITICAL"
    if level >= 12: return "HIGH"
    if level >= 9:  return "MEDIUM-HIGH"
    if level >= 6:  return "MEDIUM"
    return "LOW"


def build_payload(alert, pipeline_name, webhook_url):
    rule  = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = rule.get("level", 0)

    return {
        "pipeline":       pipeline_name,
        "severity":       severity_label(level),
        "alert_id":       alert.get("id", ""),
        "timestamp":      alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "rule_id":        rule.get("id", ""),
        "rule_level":     level,
        "rule_desc":      rule.get("description", ""),
        "rule_groups":    rule.get("groups", []),
        "agent_id":       agent.get("id", "000"),
        "agent_name":     agent.get("name", "manager"),
        "agent_ip":       agent.get("ip", ""),
        "location":       alert.get("location", ""),
        "alert":          alert,
        "_meta": {
            "script_version": "4.0",
            "sent_at":        datetime.now(timezone.utc).isoformat(),
            "webhook_url":    webhook_url,
            "pipeline":       pipeline_name,
        }
    }


# ══════════════════════════════════════════════════════════════════════
# HTTP SENDER
# ══════════════════════════════════════════════════════════════════════

def send_to_n8n(payload, webhook_url):
    try:
        body = json.dumps(payload, default=str).encode("utf-8")
    except (TypeError, ValueError) as e:
        logging.error(f"JSON serialization failed: {e}")
        return False

    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Wazuh-n8n-Integration/4.0",
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            logging.info(
                f"SENT | pipeline={payload['pipeline']} | "
                f"level={payload['rule_level']} | "
                f"rule={payload['rule_id']} | "
                f"agent={payload['agent_name']} | "
                f"severity={payload['severity']} | "
                f"HTTP {resp.status}"
            )
            return True
    except urllib.error.HTTPError as e:
        logging.error(
            f"HTTP ERROR | pipeline={payload['pipeline']} | "
            f"rule={payload['rule_id']} | {e.code} {e.reason}"
        )
        return False
    except urllib.error.URLError as e:
        logging.error(
            f"URL ERROR | pipeline={payload['pipeline']} | "
            f"rule={payload['rule_id']} | {e.reason}"
        )
        return False
    except Exception as e:
        logging.error(
            f"UNEXPECTED ERROR | pipeline={payload['pipeline']} | "
            f"rule={payload['rule_id']} | {e}"
        )
        return False


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    setup_logging()

    webhook_url   = get_webhook_url()
    pipeline_name = get_pipeline_name(webhook_url)
    alert         = read_alert()

    rule_id = alert.get("rule", {}).get("id", "N/A")
    level   = alert.get("rule", {}).get("level", 0)
    agent   = alert.get("agent", {}).get("name", "unknown")

    logging.info(
        f"RECEIVED | pipeline={pipeline_name} | "
        f"level={level} | rule={rule_id} | agent={agent}"
    )

    payload = build_payload(alert, pipeline_name, webhook_url)
    success = send_to_n8n(payload, webhook_url)
    sys.exit(0 if success else 2)


if __name__ == "__main__":
    main()