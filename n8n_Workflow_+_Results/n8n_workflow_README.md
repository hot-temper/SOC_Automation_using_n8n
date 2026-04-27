# 🛡️ Wazuh SOC Automation Pipeline — update-13

> **Automated Level 1/2 SOC triage pipeline** built on n8n + Wazuh SIEM/XDR.  
> Receives live alerts, enriches them with 5 threat-intelligence engines, runs dual AI investigation (Groq + Gemini), deduplicates burst events, and delivers structured SOC reports to Telegram — all within seconds of alert ingestion.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Pipeline Stages](#pipeline-stages)
- [Node Reference](#node-reference)
- [Threat Intelligence Engines](#threat-intelligence-engines)
- [AI Investigation Layer](#ai-investigation-layer)
- [Alert Deduplication & Burst Handling](#alert-deduplication--burst-handling)
- [Output & Reporting](#output--reporting)
- [Credentials Setup](#credentials-setup)
- [Infrastructure Requirements](#infrastructure-requirements)
- [Import & Deploy](#import--deploy)
- [Known Limitations](#known-limitations)
- [Changelog](#changelog)

---

## Overview

This workflow implements an automated **SOC Level 1/2 triage pipeline** that eliminates manual first-response effort for Wazuh SIEM alerts. It is designed to run 24/7 on a self-hosted n8n instance alongside a Wazuh Manager.

**Key capabilities:**

- Instantly ACKs Wazuh `integratord` webhook calls (200 OK) before any processing begins — preventing Wazuh timeouts
- Normalises raw Wazuh payloads across three nesting levels (raw file, standard POST, curl/test double-wrap)
- Extracts IOCs (IPs, domains, URLs, SHA-256 hashes) automatically from alert data
- Fans out to **5 threat-intelligence APIs in parallel** — AbuseIPDB, VirusTotal (IP), VirusTotal (Hash), AlienVault OTX, Hybrid Analysis
- Aggregates and scores all TI results into a single unified threat-intel object with per-engine health tracking
- Runs **primary AI investigation via Groq** (llama-3.3-70b-versatile) with **Gemini 2.5 Flash Lite as automatic fallback**
- Suppresses duplicate/burst alerts using an in-memory dedup gate with configurable TTL and flush thresholds
- Produces **structured SOC reports** delivered to Telegram (compact ~2500 chars) and optionally email (full triage report)
- Benchmarks end-to-end pipeline latency and token cost per alert — writing CSV execution logs for audit

---

## Architecture

```
Wazuh integratord
       │
       ▼  POST /webhook/wazuh-critical-groups
┌─────────────────┐
│  Webhook        │  ← n8n webhook trigger
│  Critical       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│  ACK Wazuh      │─────▶│  Enrich Alert    │  ← normalise _e object
│  (200 OK)       │      └────────┬─────────┘
└─────────────────┘               │
                                  ▼
                       ┌──────────────────┐
                       │  Alert Dedup     │  ← suppress duplicates / flush bursts
                       │  Gate            │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Extract IOCs    │  ← IPs, domains, URLs, hashes
                       └──┬───┬───┬───┬──┘
                          │   │   │   │   └────────────────────┐
                          ▼   ▼   ▼   ▼                        ▼
                      [AbuseIPDB] [VT IP] [VT Hash] [OTX] [Hybrid Analysis]
                          │   │   │   │   │
                          ▼   ▼   ▼   ▼   ▼
                       ┌──────────────────┐
                       │  Merge TI        │  ← append mode, 5 inputs
                       │  Results         │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Aggregate TI    │  ← score + unify all engine results
                       └──┬──────────────┘
                          │
              ┌───────────┴────────────┐
              ▼                        ▼
     ┌────────────────┐     ┌──────────────────┐
     │  AI Groq v2    │     │  (batch buffer)  │
     │  (Primary)     │     │  Merge node      │
     └────────┬───────┘     └────────┬─────────┘
              │                      │
              ▼                      ▼
       ┌────────────┐      ┌──────────────────┐
       │   Wait     │      │  If (Groq fail?) │
       └─────┬──────┘      └──┬───────────────┘
             │              True│        False│
             ▼                 ▼             ▼
    ┌─────────────────┐  ┌──────────┐  ┌────────────────┐
    │ Split In Batches│  │ Gemini   │  │ Parse AI Groq  │
    └──────┬──────────┘  │ Fallback │  │ + Build AUDIT  │
           │             └────┬─────┘  └───────┬────────┘
           ▼                  ▼                 │
    ┌────────────────┐  ┌──────────────┐        │
    │ Parse Gemini   │  │ Wait1        │        │
    │ Response       │  └────┬─────────┘        │
    └────────┬───────┘       │                  │
             └───────────────┘                  │
                       │                        │
                       └──────────┬─────────────┘
                                  ▼
                       ┌──────────────────┐
                       │  SOC Alert       │  ← format Telegram + email
                       │  Summarizer v5   │
                       └──┬───────────────┘
                          │
              ┌───────────┴────────────┐
              ▼                        ▼
     ┌────────────────┐      ┌──────────────────┐
     │  Send Telegram │      │  Result          │
     │  Alert         │      │  Benchmarker     │
     └────────────────┘      └────────┬─────────┘
                                      ▼
                             ┌──────────────────┐
                             │  Convert to CSV  │  ← persistent execution log
                             └──────────────────┘
```

---

## Pipeline Stages

### Stage 0 — Ingestion & ACK
The `Webhook Critical` node receives the POST from Wazuh `integratord`. The `C — ACK Wazuh` node **immediately** returns `HTTP 200` with a JSON receipt before any processing starts. This is critical — Wazuh has a short timeout on webhook calls and will retry or error if the pipeline response is slow.

### Stage 1 — Alert Normalisation
`Enrich Alert` unwraps the raw Wazuh payload across three possible nesting levels:
- **Level 1** — direct raw alert (file-based or raw Wazuh format)
- **Level 2** — standard webhook POST (`body.alert`)
- **Level 3** — curl / n8n test mode double-wrapping (`body[0].body.alert`)

It builds the unified `_e` envelope object carrying: alert metadata, rule info, MITRE ATT&CK mappings, agent/host context, network fields, syscheck diffs, vulnerability data, and compliance tags.

### Stage 2 — Deduplication Gate
`Alert Dedup Gate` provides three-state burst handling:
- **First occurrence** → forwards immediately, registers in in-memory cache (TTL: 5 min)
- **Duplicate within TTL** → accumulates attempt count and unique source IPs; silently drops unless flush condition triggers
- **Flush** → emits a synthetic enriched alert carrying full burst statistics (count, unique IPs, time window) — so AI and Telegram receive the complete brute-force/scan picture as one event

Configurable constants: `DEDUP_WINDOW_MS` (default 5 min), `FLUSH_INTERVAL_MS` (default 60 s), `FLUSH_THRESHOLD` (count-based flush).

### Stage 3 — IOC Extraction
`C — Extract IOCs` parses the full stringified alert to extract:
- **IPs** — regex match + private/reserved range filter (RFC1918, loopback, APIPA, broadcast)
- **Domains** — regex match + trusted-domain allowlist (Microsoft, Google, Akamai, Cloudflare, AWS, etc.) filtering
- **URLs** — from `full_log` field and `_seeds` context
- **SHA-256 hashes** — 64-char hex match

All IOC arrays are capped at 5 items to prevent API quota blowout. Seeds from the `_e._seeds` object (pre-tagged by Enrich Alert) take priority.

### Stage 4 — Threat Intelligence Enrichment (Parallel Fan-out)
Five TI API calls fire simultaneously from `C — Extract IOCs`:

| Engine | Node | Target |
|--------|------|--------|
| AbuseIPDB | `C — TI AbuseIPDB` | First extracted public IP |
| VirusTotal IP | `C — TI VT IP` | First extracted public IP |
| VirusTotal Hash | `C — TI VT Hash` | First SHA-256 hash |
| AlienVault OTX | `C — TI OTX` | URL → Domain → IP (dynamic routing) |
| Hybrid Analysis | `C — TI Hybrid Analysis1` | First SHA-256 hash |

Each TI node has `onError: continueRegularOutput` — API failures produce an error-labelled result rather than breaking the pipeline. Each has an 8-second timeout.

Label nodes (`C — Label *`) tag each result with `engine`, `ok`, and `rate_limited` fields before merging.


### Stage 5 — TI Aggregation & Scoring
`C — Aggregate TI` collects all 5 label results and computes a unified `threat_intel` object with:
- Per-engine status (`ok` / `error` / `rate_limited` / `skipped` / `no_response`)
- Normalised score contribution per engine (see scoring table below)
- `url_rep` section for URL-based OTX results
- Full Hybrid Analysis fields (verdict, threat score, malware families, MITRE techniques)
- Hash mismatch detection between VT and Hybrid Analysis
- Unknown engine fallback handler for extensibility

**TI Scoring Reference:**

| Engine | Condition | Score Added |
|--------|-----------|-------------|
| AbuseIPDB | score > 80 | +10 |
| AbuseIPDB | score 50–80 | +5 |
| AbuseIPDB | score 20–50 | +2 |
| AbuseIPDB | is_tor = true | +10 |
| VT IP/Domain | malicious ≥ 10 | +15 |
| VT IP/Domain | malicious 3–9 | +8 |
| VT IP/Domain | malicious 1–2 | +3 |
| VT Hash | malicious ≥ 10 | +20 |
| VT Hash | malicious 3–9 | +10 |
| VT Hash | malicious 1–2 | +4 |
| OTX | pulse_count > 0 | min(count×2, 10) |
| Hybrid Analysis | malicious verdict | +15 |

### Stage 6 — AI Investigation (Primary + Fallback)
See [AI Investigation Layer](#ai-investigation-layer) section below.

### Stage 7 — SOC Alert Summarizer
`C — SOC Alert Summarizer2` (v5) produces two output formats from the fully enriched `_e` object:

- **`tgMessage`** — Compact Telegram HTML (~2500–3000 chars) covering: alert ID/timestamp, host/network context, verdict/risk/confidence, TI verdict + engine health, MITRE ATT&CK, IOCs per engine, syscheck + vuln + compliance, recommended actions (P0–P3), investigation timeline, affected assets, analyst notes, and footer (duration, tokens, model)
- **`emailReport`** — Full structured triage report with all sections including raw IOCs (for future email node integration)

Burst alerts include an additional banner line and unique source IP list (+200–300 chars max overhead).

### Stage 8 — Output & Benchmarking
- `C — Send Telegram Alert` — POSTs the `tgMessage` to your Telegram bot
- `Result benchmarker` — Computes end-to-end pipeline duration, AI pipeline duration, token count, estimated USD cost, and rolling session statistics (in-memory, resets on n8n restart)
- `Convert to csv` — Writes a CSV execution log entry for persistent audit trail

---

## Node Reference

| Node Name | Type | Purpose |
|-----------|------|---------|
| `Webhook Critical` | Webhook | Entry point — receives Wazuh POST |
| `C — ACK Wazuh` | Respond to Webhook | Instant 200 OK to prevent Wazuh timeout |
| `Enrich Alert` | Code | Normalise payload → build `_e` envelope |
| `Alert Dedup Gate` | Code | In-memory dedup + burst flush logic |
| `C — Extract IOCs` | Code | Extract IPs, domains, URLs, hashes from alert |
| `C — TI AbuseIPDB` | HTTP Request | AbuseIPDB IP reputation check |
| `C — Label AbuseIPDB` | Code | Tag AbuseIPDB result |
| `C — TI VT IP` | HTTP Request | VirusTotal IP lookup |
| `C — Label VT IP` | Code | Tag VT IP result |
| `C — TI VT Hash` | HTTP Request | VirusTotal hash/file lookup |
| `C — Label VT Hash` | Code | Tag VT Hash result |
| `C — TI OTX` | HTTP Request | AlienVault OTX (dynamic: URL/domain/IP) |
| `C — Label OTX` | Code | Tag OTX result |
| `C — TI Hybrid Analysis1` | HTTP Request | Hybrid Analysis hash report |
| `C — Label Hybrid` | Code | Tag Hybrid Analysis result |
| `C — Merge TI Results` | Merge | Append-mode, 5 inputs → collect all labels |
| `C — Aggregate TI` | Code | Score + unify all TI results → `threat_intel` |
| `Merge` | Merge | Batch buffer before AI routing |
| `Split In Batches` | Split In Batches | Rate-limit Groq calls |
| `Wait` | Wait | Groq rate-limit delay |
| `C — AI Investigation Groq v2` | HTTP Request | Primary AI — Groq llama-3.3-70b-versatile |
| `If (True when Main AI fail)` | If | Route to fallback if Groq fails |
| `C — Parse AI + Build AUDIT_1` | Code | Parse Groq response + build AUDIT record |
| `Split In Batches1` | Split In Batches | Rate-limit Gemini calls |
| `Wait1` | Wait | Gemini rate-limit delay |
| `Edit Fields` | Set | Prepare payload for Gemini |
| `AI Investigation gemini-2.5-flash` | HTTP Request | Fallback AI — Gemini 2.5 Flash Lite |
| `Code in JavaScript` | Code | Deduplicate Gemini multi-item output |
| `Parse AI Fallback Response2` | Code | Parse Gemini response + build AUDIT record |
| `C — SOC Alert Summarizer2` | Code | Format Telegram + email report (v5) |
| `C — Send Telegram Alert` | HTTP Request | Deliver report to Telegram bot |
| `Result benchmarker` | Code | Compute E2E latency, tokens, cost |
| `Convert to csv` | Convert to File | Write CSV execution log entry |
| `DOC — *` | Sticky Note | Inline documentation nodes |

---

## Threat Intelligence Engines

### AbuseIPDB
- **Endpoint:** `https://api.abuseipdb.com/api/v2/check`
- **Parameters:** `maxAgeInDays=90`, `verbose=true`
- **Auth:** HTTP Header Auth — header name: `Key`
- **Credential name in n8n:** `Header Auth account`

### VirusTotal (IP & Hash)
- **IP Endpoint:** `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- **Hash Endpoint:** `https://www.virustotal.com/api/v3/files/{sha256}`
- **Auth:** VirusTotal API credential (n8n native)
- **Credential name in n8n:** `VirusTotal account`

### AlienVault OTX
- **Endpoint:** Dynamic — routes to URL, domain, or IPv4 indicator type based on available IOCs
- **Auth:** AlienVault OTX API credential (n8n native)
- **Credential name in n8n:** `AlienVault account`

### Hybrid Analysis
- **Endpoint:** `https://www.hybrid-analysis.com/api/v2/report/{sha256}/summary`
- **Auth:** HTTP Header Auth — header name: `api-key`
- **Credential name in n8n:** `Header Auth account 3`

---

## AI Investigation Layer

### Primary — Groq (llama-3.3-70b-versatile)
- **Endpoint:** `https://api.groq.com/openai/v1/chat/completions`
- **Model:** `llama-3.3-70b-versatile`
- **Settings:** `temperature: 0`, `max_tokens: 2000`, `response_format: json_object`
- **Role:** SOC Level 2 Security Analyst persona
- **Input:** Full `_e` object — alert details, MITRE mappings, compliance tags, host/network context, all TI engine results, syscheck diffs, vulnerability data
- **Credential:** Groq API key stored directly in node Authorization header (replace placeholder after import)

**AI Output Schema:**
```json
{
  "alert_verdict": "TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_INVESTIGATION | BENIGN",
  "risk_score": 0-100,
  "confidence": "HIGH | MEDIUM | LOW",
  "incident_severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "attack_type": "string",
  "mitre_attack": {
    "tactics": ["TA00xx"],
    "techniques": ["T1xxx"]
  },
  "ioc_analysis": "string",
  "recommended_actions": {
    "P0": ["immediate actions"],
    "P1": ["short-term actions"],
    "P2": ["medium-term actions"],
    "P3": ["long-term actions"]
  },
  "analyst_notes": "string",
  "alert_summary": "string"
}
```

### Fallback — Gemini 2.5 Flash Lite
- **Endpoint:** `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent`
- **Trigger:** `If (True when Main AI fail)` routes here when Groq returns an error or empty response
- **Settings:** `temperature: 0`, `responseMimeType: application/json`
- **Parser:** `Parse AI Fallback Response2` extracts from `candidates[0].content.parts[0].text`
- **Credential:** Gemini API key passed as URL query parameter (`?key=<YOUR_GEMINI_API_KEY>`)

The fallback maintains the same output schema as the primary so `C — SOC Alert Summarizer2` receives identical structure regardless of which AI model was used.

---

## Alert Deduplication & Burst Handling

The `Alert Dedup Gate` node implements a stateful in-memory cache (persists for the duration of the n8n process):

```
Config defaults:
  DEDUP_WINDOW_MS   = 300,000  (5 minutes)
  FLUSH_INTERVAL_MS = 60,000   (60 seconds)
  FLUSH_THRESHOLD   = <count>  (flush on N duplicates)
```

**Three states:**
1. **PASS** — New alert not seen in cache → forward immediately, register
2. **DROP** — Duplicate within TTL, below flush threshold and flush interval → silently drop
3. **FLUSH** — Duplicate exceeding threshold or interval → emit synthetic burst summary alert carrying `burst_count`, `unique_src_ips`, `burst_window_ms`, and `dedup_intel` fields

Burst data is surfaced in the `SOC Alert Summarizer` Telegram output as a banner line plus unique IP list, giving analysts full situational awareness without alert fatigue.

> ⚠️ Cache is in-memory — restarting n8n resets all dedup state. Consider externalising to Redis for production deployments.

---

## Output & Reporting

### Telegram Report Structure
```
[ALERT ID] [TIMESTAMP]
─────────────────────────────
HOST: <hostname> | AGENT: <id>
IP: <src_ip> → <dst_ip>
VERDICT: <TRUE_POSITIVE> | RISK: <score>/100 | CONF: <HIGH>

[BURST BANNER if applicable]
Unique sources: x.x.x.x, y.y.y.y ...

TI VERDICT: <MALICIOUS> | Engines: 5/5 healthy
ATTACK: <attack_type>
MITRE: <TA00xx> / <T1xxx>

IOCs:
  IP:     x.x.x.x  [AbuseIPDB: 95 | VT: 12 malicious]
  Hash:   abc123..  [VT: CONFIRMED | Hybrid: MALICIOUS]
  Domain: evil.com  [OTX: 8 pulses]

SYSCHECK: <file changes if any>
VULN:     <CVE if any>
COMPLIANCE: <PCI/GDPR/HIPAA tags>

ACTIONS:
  P0 (Immediate): Block IP, isolate host
  P1 (1hr):       ...
  P2 (24hr):      ...
  P3 (Long-term): ...

TIMELINE:
  [timestamps of investigation steps]

ANALYST NOTES: <AI-generated context>

─────────────────────────────
⏱ 8.3s | 1,847 tokens | llama-3.3-70b | $0.0011
```

### CSV Execution Log
Written via `Convert to csv` node — one row per processed alert containing: `alert_id`, `timestamp`, `rule_id`, `rule_level`, `agent_id`, `verdict`, `risk_score`, `e2e_duration_s`, `ai_duration_s`, `token_count`, `cost_usd`, `model_used`, `ti_engines_ok`, `burst_count`.

---

## Credentials Setup

After importing the workflow, create the following credentials in **n8n → Settings → Credentials**:

| Credential Name | Type | Field | Value |
|----------------|------|-------|-------|
| `Header Auth account` | HTTP Header Auth | Name: `Key` | Your AbuseIPDB API key |
| `VirusTotal account` | VirusTotal API | API Key | Your VT API key |
| `AlienVault account` | AlienVault OTX API | API Key | Your OTX API key |
| `Header Auth account 3` | HTTP Header Auth | Name: `api-key` | Your Hybrid Analysis key |

**API keys stored directly in node headers (edit after import):**

- `C — AI Investigation Groq v2` → Headers → Authorization → `Bearer <YOUR_GROQ_API_KEY>`
- `AI Investigation gemini-2.5-flash` → URL → `?key=<YOUR_GEMINI_API_KEY>`

**Telegram configuration (in `C — Send Telegram Alert` node):**

- URL: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/sendMessage`
- Body: `chat_id` → `<YOUR_CHAT_ID>`

> Get your bot token from [@BotFather](https://t.me/BotFather) on Telegram.  
> Get your chat ID by messaging [@userinfobot](https://t.me/userinfobot).

---

## Infrastructure Requirements

| Component | Requirement |
|-----------|-------------|
| n8n | Self-hosted, v1.x+ recommended |
| Wazuh Manager | Configured with `integratord` webhook pointing to n8n |
| n8n host | Reachable from Wazuh Manager on port `5678` |
| Webhook path | `/webhook/wazuh-critical-groups` |
| Wazuh alert level | Set `level` threshold in `ossec.conf` integratord block |

**Wazuh `ossec.conf` integration block (reference):**
```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://<N8N_HOST>:5678/webhook/wazuh-critical-groups</hook_url>
  <level>9</level>
  <alert_format>json</alert_format>
</integration>
```

---

## Import & Deploy

1. **Clone or download** this repository
2. Open your n8n instance → **Workflows → Import from file**
3. Select `update-13-public.json`
4. **Set all credentials** as described in [Credentials Setup](#credentials-setup)
5. **Edit Telegram node** — replace `<YOUR_BOT_TOKEN>` and `<YOUR_CHAT_ID>`
6. **Edit Groq node** — replace `<YOUR_GROQ_API_KEY>` in the Authorization header
7. **Edit Gemini node** — replace `<YOUR_GEMINI_API_KEY>` in the URL parameter
8. **Activate** the workflow
9. Configure Wazuh `integratord` to POST to your n8n webhook URL
10. **Test** by sending a sample alert payload:

```bash
curl -X POST http://<N8N_HOST>:5678/webhook/wazuh-critical-groups \
  -H "Content-Type: application/json" \
  -d '{"rule":{"id":"5710","level":10,"description":"SSH brute force"},"agent":{"id":"001","name":"web-server-01"},"data":{"srcip":"198.51.100.42"}}'
```

---

## Known Limitations

- **Dedup cache is in-memory** — restarting n8n clears all suppression state
- **AbuseIPDB label node is working perfectly** — enabled in `C — Label AbuseIPDB` checks for ip status
- **Single IOC per engine** — only the first extracted IP/hash is queried per alert to respect free-tier API rate limits
- **Groq free-tier rate limits** — the `Split In Batches` + `Wait` pattern throttles calls; adjust batch size and wait duration for paid tiers
- **No persistent TI cache** — identical IOCs are re-queried on every alert; add a Redis/database lookup to reduce API calls in high-volume environments
- **CSV log resets on restart** — the in-memory session stats in `Result benchmarker` reset when n8n restarts; the CSV file persists if written to a mounted volume

---

## Changelog

### update-13 (current)
- Added Gemini 2.5 Flash Lite as automatic AI fallback when Groq fails
- Added `If (True when Main AI fail)` routing node
- Added `Parse AI Fallback Response2` for Gemini response parsing
- Added `Split In Batches1` + `Wait1` rate limiting for Gemini path
- Added `Code in JavaScript` to deduplicate Gemini multi-item output
- SOC Alert Summarizer bumped to v5 — integrates burst/dedup intel from Alert Dedup Gate
- Burst banner + unique source IPs added to Telegram output
- Result benchmarker updated to v4.1 with CSV export pipeline

### Earlier versions (reference)
- **update-12:** Added Alert Dedup Gate with three-state burst aggregation
- **update-11:** Added Result benchmarker + CSV execution log
- **update-10:** Full workflow rebuild — fixed 7 broken nodes across IOC extraction, TI, AI, audit, summarizer, and Telegram output
- **update-9:** Initial 5-engine parallel TI fan-out with Aggregate TI scoring

---

## Author

**Saif Ahmed Shuvo**  
Final-year CSE Student | Cybersecurity & SOC Automation  
GitHub: [@hot-temper](https://github.com/hot-temper)

---

*Built as a Final Year Project demonstrating AI-augmented SOC automation using open-source tooling.*
