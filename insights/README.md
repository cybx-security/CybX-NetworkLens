# CybX Network Scanner → CybX Insight (collector setup)

This folder contains the one-time setup that connects this scanner to the
**CybX Insight** dashboard. It's engineer-facing: a CybX engineer installs it once
per environment. Operators running scans never touch this.

Insight surfaces network data by reading events tagged
`data.integration: "nmap_chat"`, one row per open port (see `getNetworkEvents` in
the Insight project). This scanner produces exactly those events.

> **Backend note.** CybX Insight's collector runs on a Wazuh/OSSEC engine. The
> commands and paths below (`/var/ossec/...`, `systemctl restart wazuh-manager`,
> etc.) are that engine's real service names — they're what you actually type
> during setup. Everywhere the *product* is meant, it's **Insights**.

## The data flow

```
 nmap  ─►  CybX Network Scanner  ─►  events.ndjson  ─►  Insights collector (agent, json)
                                                              │
                                                              ▼
                                                    Insights collector (decoders + these rules)
                                                              │
                                                              ▼
                                                    Insights datastore  ◄──  CybX Insight
                                                                              (Network Discovery view)
```

The scanner writes **NDJSON** — one compact JSON object per line. That is what the
collector's built-in `json` decoder expects; a pretty-printed multi-line document
would not decode. No custom decoder is needed — the stock `json` decoder parses
each line and the rules here classify it by risk.

## Event shape (one per open port)

```json
{"integration":"nmap_chat","scan":{"target":"192.168.1.0/24","scanner_version":"1.0.0","time":"2026-07-22T14:09:34Z"},"insights_level_hint":13,"nmap":{"host":"192.168.1.50","hostname":"fileserver.local","os_guess":"Microsoft Windows Server 2008 R2 SP1","port":445,"protocol":"tcp","service":"microsoft-ds","product":"","version":"","state":"open","risk":"critical","cve_ids":[],"nse_results":""},"ai_assessment":{"summary":"Port 445/tcp (microsoft-ds): SMB is exposed...","risk_level":"critical","findings":["..."],"recommendations":["..."],"source":"local"}}
```

Once the collector decodes it, the keys land under `data.*`, so Insight sees
`data.integration`, `data.nmap.host`, `data.nmap.os_guess`, `data.nmap.port`,
`data.nmap.protocol`, `data.nmap.nse_results`, and `data.ai_assessment` — the
exact fields the dashboard maps to a `NetworkEvent`. `agent.id`, `agent.name`,
`rule.*` and the alert `timestamp` are filled in by the collector, not the scanner.

## Files in this folder

| File | Where it goes | Needed? |
|------|---------------|---------|
| [`cybx_nmap_chat_rules.xml`](cybx_nmap_chat_rules.xml) | collector `/var/ossec/etc/rules/` | **Yes** — makes events alert so Insight can see them |
| [`cybx_nmap_chat_decoders.xml`](cybx_nmap_chat_decoders.xml) | collector `/var/ossec/etc/decoders/` | Optional — only if you ingest as plain text instead of `log_format json` |
| [`ossec_localfile_snippet.xml`](ossec_localfile_snippet.xml) | collector agent config | **Yes** — tells the collector to tail the NDJSON file |

## Setup (once per environment)

1. **Collector (manager side)** — install the rules (and, only if you are not using
   `log_format json`, the optional decoder):
   ```bash
   sudo cp cybx_nmap_chat_rules.xml /var/ossec/etc/rules/
   # optional, text-ingestion only:
   # sudo cp cybx_nmap_chat_decoders.xml /var/ossec/etc/decoders/
   sudo systemctl restart wazuh-manager
   ```
2. **Collector (agent side)** — on the box you run the scanner on, tell the
   collector to tail the NDJSON file. Copy the `<localfile>` block matching the
   scanner box's OS from
   [`ossec_localfile_snippet.xml`](ossec_localfile_snippet.xml) into the agent
   config, then restart the collector agent:

   | OS | Agent config file | Restart command |
   |----|-------------------|-----------------|
   | Windows | `C:\Program Files (x86)\ossec-agent\ossec.conf` | `Restart-Service WazuhSvc` (PowerShell, as Administrator) |
   | Linux | `/var/ossec/etc/ossec.conf` | `systemctl restart wazuh-agent` |

3. **Scanner** — point it at that same file so scanner and collector agree. Edit
   the scanner's config file — for an installed copy on Windows that is
   `C:\ProgramData\CybX\Network Scanner\config.json` (edit as Administrator; it
   survives upgrades); when running from source it is `config/config.json`:

   Windows scanner box (JSON needs `\\` — or use forward slashes, both work):
   ```json
   "output": {
     "insights_events": { "enabled": true, "path": "C:\\ProgramData\\CybX\\Insights\\nmap_chat.ndjson" }
   }
   ```

   Linux scanner box:
   ```json
   "output": {
     "insights_events": { "enabled": true, "path": "/var/log/insights/nmap_chat.ndjson" }
   }
   ```

   Use whatever path you configured the collector to tail in step 2 — the two
   must match character for character; the scanner creates the folder if it
   doesn't exist. (`C:\ProgramData` is the Windows equivalent of `/var`: it's
   machine-wide, survives user-profile changes, and the collector agent service
   can read it.) When `path` is set, the scanner **appends** to that file each
   run, so the collector tails only new lines. Leave `path` empty to instead
   get a fresh per-scan `.ndjson` next to the JSON report (handy for
   manual/offline import).

## Verify

- On the collector: `sudo /var/ossec/bin/wazuh-logtest` then paste one event line —
  it should match rule `100200` and one of `100201`–`100205`.
- In Insight: filter `data.integration: nmap_chat`; new port rows should appear
  under the Network Discovery view for the collector that shipped them.

## Rule → risk → alert level

| `nmap.risk` | Rule id | Alert level |
|-------------|---------|-------------|
| info        | 100201  | 3  |
| low         | 100202  | 5  |
| medium      | 100203  | 8  |
| high        | 100204  | 10 |
| critical    | 100205  | 13 |

`info` fires at level 3 (not lower) so every open port clears the collector's
default alert threshold and reaches the index Insight queries — otherwise low-risk
ports would be missing from the network landscape.

Insight matches on `data.integration: "nmap_chat"`, **not** on a rule id, so these
ids are free to change if they collide with other custom rules on your collector
(they live in the 100000+ user range).
