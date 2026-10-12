# Seismic Framework in Microsoft Defender XDR — Live Tenant Operations Manual

**Version 1.0 · 2026-10-11**
Artifacts: `seismic-xdr.kql` v1.1 (9 validated queries) · Basis: Working Document v3.1 · Validation: `KQL_VALIDATION_REPORT.md`
Scope: everything from "I have a tenant" to "it alerts, dashboards, and feeds the SOC" — every portal click, every setting, every pitfall.

---

## PART 0 — Prerequisites checklist

Before touching a query, confirm all six:

| # | Requirement | How to verify |
|---|---|---|
| 1 | **License**: Microsoft Defender for Endpoint P2 (standalone) or any Defender XDR suite (E5, E5 Security, Business Premium+Defender for Business servers, etc.) | Portal → **Settings → Microsoft Defender XDR → Licenses**; Advanced hunting menu exists at all only if licensed |
| 2 | **RBAC — hunting**: role with *Security data / read* permissions — built-in Entra roles: **Security Reader** (hunt), **Security Analyst** (hunt + save), **Security Administrator** (custom detections + actions). Custom RBAC: "Security operations → Security data → Security data basics (read)" and "Alerts (manage)" for detections | Entra admin center → Roles & administrators, or Defender **Settings → Roles** if using Defender XDR Unified RBAC |
| 3 | **Devices onboarded** to Defender for Endpoint (otherwise `DeviceNetworkEvents` is empty) | Portal → **Assets → Devices** shows onboarded fleet |
| 4 | **Data flowing**: `DeviceNetworkEvents` populated | Run smoke query §1.2 |
| 5 | **Retention reality**: Advanced hunting sees **last 30 days only**. No exceptions, regardless of license. Longer baselines must be exported (§5.4) | — |
| 6 | **Permissions for API automation** (optional, Part 6): ability to register an app in Entra ID and grant admin consent | Entra → App registrations |

### RBAC quick map for this pack

| Persona | Needs | Give them |
|---|---|---|
| Threat hunter (runs Q1–Q6) | Hunt, save queries | Security Analyst |
| Detection engineer (Q7 rule) | Manage custom detections | Security Administrator |
| Automation (Part 6) | App permission | `AdvancedHunting.Read.All` (Defender API) or `ThreatHunting.Read.All` (Graph) |
| Read-only exec dashboard | View | Security Reader |

## PART 1 — First contact: the Advanced hunting editor

### 1.1 Open it

1. Go to **https://security.microsoft.com**
2. Left nav → **Hunting** → **Advanced hunting**
3. You see: left pane (**Schema**, **Functions**, **Queries**, **Detection rules** tabs), center = query editor, bottom = results grid (max 10,000 rows displayed).

### 1.2 Smoke test (60 seconds)

Paste and **Run query**:

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where isnotempty(RemoteIP)
| summarize Events = count(), Devices = dcount(DeviceId) by ActionType
| order by Events desc
```

**Expected:** rows for `ConnectionSuccess`, `ConnectionFailed`, maybe `ConnectionAttempt`/`InboundConnectionAccepted`, with device counts. If zero rows for a busy fleet, network events aren't flowing (check onboarding, and note macOS/Linux endpoints emit fewer network events than Windows). If you see data → proceed.

### 1.3 Confirm the schema matches the pack

In the left **Schema** tab, expand `DeviceNetworkEvents` and confirm these columns exist (they are what the pack was validated against): `Timestamp`, `DeviceId`, `DeviceName`, `ActionType`, `RemoteIP`, `RemotePort`, `LocalIP`, `Protocol`, `RemoteIPType`, `LocalIPType`, `InitiatingProcessFileName`, `ReportId`. All are documented GA columns — but confirm `RemoteIPType` exists in your tenant before running Q7 (it is the one most likely to be absent in older/limited licenses; if missing, replace `where RemoteIPType == "Public"` with an RFC1918 regex exclusion shown in §7.2).

## PART 2 — Installing the pack (30 minutes)

You will create **2 functions** and **7 saved queries**. Convention: prefix everything `Seismic_` so it groups in the UI.

### 2.1 Create folder structure

In the **Queries** tab → **Shared queries** → new folder `Seismic Framework`. (Shared, not My queries — your team needs these.)

### 2.2 Save the two functions

**Function 1 — `SeismicFlows`** (the Q0 block):

1. Paste the **Q0** section from `seismic-xdr.kql` into a new query tab (everything from `let Lookback = 24h;` through the final `Flows`).
2. Replace the final bare `Flows` line with `Flows` — it already ends that way; test-run it once to confirm rows return.
3. Click **Save** dropdown → **Save as function**.
4. Name: `SeismicFlows` (names: letters, digits, underscores only — no spaces). Location: **Shared functions**. Description: "Seismic pack Q0 — direction-normalized, IPv4-keyed network event stream".
5. **Save**.

**Function 2 — `SeismicEta`** (the Q1 computation, minus presentation):

1. Paste **Q1** but truncate after the `| extend LogEta = log10(EtaMin)` line — i.e., drop the `Class`, `where Class ==`, `project ...`, `order by`, `take` lines. The function must return *all* scored rows with `LogEta`, so Q6 can compose on it.
2. Test-run (scope: it will be slow on big catalogs — see §7.1 if it times out).
3. **Save as function** → name `SeismicEta`, shared, description "Seismic pack Q1 core — Zaliapin eta score per event".

> Why functions: Q6 references `SeismicEta` by name; keeping the 4-partition η logic in one function means fixes land once. Note: functions saved under **Sentinel workspace functions** cannot be used in custom detections — keep ours in **Shared functions** (Defender).

### 2.3 Save the hunting queries

For each remaining section (Q2, Q3, Q4, Q5, Q5b, Q7), paste into a new tab, test-run, then **Save query → Save as** into the `Seismic Framework` shared folder with names: `Seismic_Q2_EtaValleyHistogram`, `Seismic_Q3_M3BlastRadius`, `Seismic_Q4_BValueGauge`, `Seismic_Q5_DeviceRegimes`, `Seismic_Q5b_RemoteRegimes`, `Seismic_Q7_M3DetectionSource`.

Q1 as a full triage queue also gets saved (`Seismic_Q1_TriageQueue`) — the standalone version, not just the function.

## PART 3 — Calibration (Days 1–14, silent)

**Do not skip this. The validation report showed the η distribution shifts under XDR's schema; running Q1 with the fallback valley on an uncalibrated tenant is the one way to get a misleading first impression.**

### Day 1 — η histogram (Q2)

1. Open `Seismic_Q2_EtaValleyHistogram`. It runs the Q1 pipeline and renders `count()` by 0.1-wide bins of `LogEta` as a column chart.
2. Run it at your busiest hour and again at your quietest hour.
3. **Read the chart:**
   - **Two humps with a dip between** → healthy. The dip = your valley. Set `ValleyLogEta` in Q1/`SeismicEta` to the dip's x value (e.g., `-1.2`).
   - **One hump** → your catalog lacks a repeating-background population at this scope (common on single-subnet scopes). Widen scope to 24h/full fleet and retry. Still one hump → keep fallback `0.08` and rely on ranking (top-N) rather than the threshold.
4. Record the valley in your ops wiki with the date and scope.

### Days 1–7 — b-value baseline (Q4)

1. Open `Seismic_Q4_BValueGauge`, set `Lookback = 7d`, run. It renders a timechart of b per 30-min window with R².
2. Export results (**Export** → CSV) weekly — this is your baseline archive (AH only holds 30 days).
3. After 7 quiet days, compute mean(b) and σ(b). Our reference points: background radiation 0.19 ± 0.04; enterprise catalog 0.70. Yours will differ — that's the fingerprint.
4. Set alarm band: baseline ± 2σ.

### Days 7–14 — regime census + replay

1. Run `Seismic_Q5_DeviceRegimes` (24h) and `Seismic_Q5b_RemoteRegimes` (24h). Export both. **Expect to find some `omori_decay` and `periodic_beacon` rows in a healthy network** — investigate the top few to build local intuition (common benign causes: software update checkers = beacons; crash-reporter retry loops = omori_decay).
2. **The critical test — replay a known incident.** Pick a confirmed past incident inside your 30-day window (or run a controlled purple-team exercise). Open `Seismic_Q1_TriageQueue` scoped to that day and the affected subnet (add `| where LocalIP startswith "10.10."`). Confirm: the intrusion's C2/exfil rows appear in the top ~150, and `Seismic_Q5b` classifies the C2 host as `omori_decay` or `periodic_beacon`.
   - If yes → your calibration is real. Proceed to Part 4.
   - If no → check (a) the incident's traffic actually traversed onboarded devices, (b) valley from Day 1, (c) scope. Do not proceed to alerting until a replay passes.

## PART 4 — Daily operations

### 4.1 Analyst morning queue (Q1/Q6)

1. Open `Seismic_Q1_TriageQueue` (or Q6 for the device-level combined score — requires `SeismicEta` function).
2. Default scope 24h. Top rows = highest log₁₀η = events belonging to no recent repetition pattern.
3. For each suspicious row: the pack already carries `InitiatingProcessFileName` — one click on the device name pivots to the device page; use **Go to hunt** from any result row to pivot into `DeviceProcessEvents` around that Timestamp.
4. Reading guide (from validation): intrusion clusters appear as **contiguous blocks** of rows sharing a RemoteIP within the top ~150 — a lone rank-200 row is weaker evidence than a 15-row block at ranks 117–146.

### 4.2 Weekly regime watchlist (Q5/Q5b)

1. Run Q5/Q5b Monday, export CSV, diff against last week's export (any spreadsheet or a Sentinel watchlist join — §5.3).
2. **New `omori_decay` or `periodic_beacon` entries = investigations.** Benign explanations exist (update agents, health probes) — the first weeks are for building your local whitelist.
3. Hosts that *flip* class (poisson→anything) matter more than hosts that are always bursty.

### 4.3 b-value gauge review (Q4)

Weekly: run Q4, compare to baseline band. Excursion playbook (Deployment Guide P3): b-drop = shift toward large blast-radius events → check Q3 for the week's top M3 devices and Q5b for new external `bursty_cluster` hosts. Expect false excursions from mass deployments/updates — correlate with change calendar.

## PART 5 — Alerting: the custom detection (Q7)

### 5.1 Create the rule (portal wizard)

1. **Hunting → Advanced hunting**, open `Seismic_Q7_M3DetectionSource`, run it once to confirm it returns rows only when a device touches ≥50 public IPs in 10 min.
2. Click **Create detection rule** (top right).
3. Wizard page 1 — alert details:
   - **Detection name**: `Seismic M3 blast-radius spike`
   - **Frequency**: choose **Continuous (NRT)** if the wizard offers it (see constraints below), else **Every hour** (which gives a 4-hour lookback — correct for a 10-min binning window).
   - **Alert title**: `Device touched ≥50 public IPs in 10 min (seismic M3 spike)`
   - **Severity**: Medium (raise to High if your replay showed real incidents firing it)
   - **Category**: Suspicious activity · **MITRE tactic**: Command and Control (or Discovery) · **Technique**: T1071 / T1046
   - **Description + recommended actions**: paste the P2 playbook text.
4. Page 2 — **impacted entities**: map `DeviceId` → Device, `DeviceName` → Device name. (This is why Q7 keeps `Timestamp`, `ReportId`, `DeviceId` via `arg_max` — the wizard rejects queries that drop them.)
5. Page 3 — **actions**: leave empty for the first month (no auto-isolate — remember: prioritization layer, not gate).
6. **Scope**: all devices (or your pilot device group).
7. Review → **Create**.

**⚠ Initial-scan flood warning:** when a rule is saved, Defender runs it over the past 30 days immediately. Q7 ships with `| where ingestion_time() > ago(1d)` as a guard — keep it until the rule proves quiet, then remove it.

**NRT eligibility checklist** (the wizard enforces these): single table ✓ (DeviceNetworkEvents only); no joins/unions/`externaldata` ✓; **no comments** — strip all `//` lines when pasting into the wizard ✓; GA columns only ✓ (all columns in Q7 are GA). If NRT is rejected, run hourly — detection delay ≤ 1h + 4h lookback, acceptable for this signal.

### 5.2 What NOT to alert on

- **Q1 (η queue) as a detection** — the 4-partition + 4-join query is too expensive for scheduled rules and will hit CPU quota. It is a hunting instrument.
- **b-value excursions as auto-alerts** in month 1 — baseline first, alarm in month 2, and route to a Teams channel rather than the incident queue until precision is proven.

### 5.3 Sentinel integration (optional)

If you run Microsoft Sentinel in the Defender portal:

- **Analytics rule** alternative: Microsoft Sentinel → Configuration → Analytics → + Create → **NRT query rule** can run the same Q7 logic with watchlist support (e.g., exclude whitelisted update-server subnets).
- **Workbook for the b-gauge**: schedule Q4 via the API (Part 6) into a custom log table (`SeismicBGauge_CL`), then a Sentinel workbook line chart with a ±2σ reference band. This gives the "seismic station" wall display.
- **Watchlists**: `SeismicKnownBenignBeacons` (IPs/hostnames) joined in Q5b to suppress known-good periodic beacons.

## PART 6 — Automation via API (optional)

For scheduled runs, dashboards, or pushing results to your data lake:

### 6.1 App registration (10 minutes)

1. **Entra admin center → App registrations → New registration** → name `SeismicHuntingApp`.
2. **API permissions → Add a permission → APIs my organization uses → `WindowsDefenderATP`** → Application permissions → `AdvancedQuery.Read.All` → **Grant admin consent**.
   (Alternative: Microsoft Graph → `ThreatHunting.Read.All` → endpoint `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` — use Graph if you also need Sentinel tables in the same call.)
3. **Certificates & secrets** → create secret (or upload certificate — preferred) → note TenantId, ClientId, secret.

### 6.2 Run Q4 every 6 hours (PowerShell sample)

```powershell
$AppID = "<clientId>"; $TenantID = "<tenantId>"; $Secret = "<secret>"
$KQL = Get-Content .\Seismic_Q4_BValueGauge.kql -Raw
$body = @{ resource='https://api.security.microsoft.com'; client_id=$AppID;
           client_secret=$Secret; grant_type='client_credentials' }
$tok = (Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantID/oauth2/token" -Body $body).access_token
$resp = Invoke-RestMethod -Method Post `
        -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
        -Headers @{ Authorization="Bearer $tok"; 'Content-Type'='application/json' } `
        -Body (ConvertTo-Json @{ Query = $KQL })
$resp.Results | Export-Csv ".\bgauge_$(Get-Date -Format yyyyMMdd_HHmm).csv" -NoTypeInformation
```

Schedule with Task Scheduler / Azure Automation / a Logic App (HTTP action with managed identity). Same pattern works for Q3/Q5/Q5b exports.

### 6.3 Rate limits

The hunting API is throttled per tenant (queries per minute and CPU minutes per hour — exact quotas shown in the portal's **Query resources report**, top bar of Advanced hunting). Q3/Q4/Q5 are cheap; schedule Q1-style partition queries at most a few times per day.

## PART 7 — Troubleshooting

### 7.1 Query timeouts / CPU quota (Q1, Q6)

Ladder, in order: (1) reduce `Lookback` 24h→12h→6h; (2) uncomment the `RemoteIPType == "Public"` filter in Q0/Q1; (3) add a subnet scope `| where LocalIP startswith "10."` or `ipv4_is_in_range(RemoteIP, ...)`; (4) if `partition hint.strategy=native` is rejected or slow on your tenant, replace with single-device scope (`where DeviceId == "<id>"`) + plain `order by Timestamp asc | serialize | extend ... prev(...)`; (5) last resort for full-catalog η: stream logs out via **Defender streaming API → Event Hubs** and run `seismic_pipeline.py --zeek` externally (the reference implementation — validated against this KQL in the simulation report).

### 7.2 Column or function errors

| Error text | Cause | Fix |
|---|---|---|
| `'RemoteIPType' does not refer to any known column` | older license/schema | replace with `where RemoteIP !matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)"` |
| `'floor' expects 2 arguments` | stale pack version | re-download `seismic-xdr.kql` v1.1 (fixed) |
| `partition ... legacy strategy caps` | tenant rejects `hint.strategy=native` | single-device scope pattern (§7.1 #4) |
| Wizard rejects Q7 at **Create detection rule** | missing `Timestamp`/`ReportId`/`DeviceId` | use v1.1 Q7 verbatim (arg_max keeps them); remove `//` comments for NRT |
| Empty results everywhere | devices not onboarded / wrong table | §1.2 smoke test |

### 7.3 Suspicious-looking healthy results

- **Many `periodic_beacon` devices**: normal — Windows/Office telemetry, update agents. Whitelist via Sentinel watchlist (§5.3).
- **Valley histogram single-humped**: scope too narrow (§3 Day 1).
- **b-value jumps at patch Tuesday / deployments**: expected — correlate with change calendar before escalating.

## PART 8 — Go-live checklist (print this)

```
[ ] 0.1  License confirmed (Defender for Endpoint P2 / XDR)
[ ] 0.2  Roles assigned (Analyst / Administrator)
[ ] 1.2  Smoke query returns rows
[ ] 1.3  Schema columns confirmed
[ ] 2.2  Functions saved: SeismicFlows, SeismicEta (Shared functions, NOT Sentinel workspace)
[ ] 2.3  7 queries saved under Shared queries / Seismic Framework
[ ] 3.D1 Q2 valley recorded (or fallback documented)
[ ] 3.D7 b baseline mean/sigma recorded, exported
[ ] 3.D14 Replay of known incident PASSED (top-150 queue + C2 regime)
[ ] 4    Playbooks P1-P3 assigned to named analysts
[ ] 5.1  Q7 custom detection created (NRT or hourly), entities mapped, no actions
[ ] 5.1  ingestion_time() guard removed after quiet period
[ ] 5.2  No eta/b-value auto-alerts in month 1
[ ] 6    (Optional) API app registered, Q4 scheduled, workbook live
[ ] —    First monthly review: rule precision, whitelist growth, baseline drift
```

## Appendix A — Query inventory

| Saved name | Source section | Runs where | Cadence |
|---|---|---|---|
| `SeismicFlows` (function) | Q0 | — | referenced |
| `SeismicEta` (function) | Q1 core | — | referenced |
| `Seismic_Q1_TriageQueue` | Q1 | Advanced hunting | daily hunting |
| `Seismic_Q2_EtaValleyHistogram` | Q2 | Advanced hunting | calibration only |
| `Seismic_Q3_M3BlastRadius` | Q3 | AH + API | daily/API 6h |
| `Seismic_Q4_BValueGauge` | Q4 | AH + API → workbook | API 6h |
| `Seismic_Q5_DeviceRegimes` | Q5 | AH + API | weekly |
| `Seismic_Q5b_RemoteRegimes` | Q5b | AH + API | weekly |
| `Seismic_Q7_M3DetectionSource` | Q7 | Custom detection rule | NRT/hourly |

## Appendix B — Fidelity contract

This pack is validated, not merely written (see `KQL_VALIDATION_REPORT.md`): all 9 queries pass Microsoft's official KQL grammar+semantic analyzer; the exact logic reproduces the ground-truth results (M3 = 2.000 on the AMOS victim; the C2 host classifies `omori_decay` via Q5b) on simulated `DeviceNetworkEvents` data. Known deltas vs the Python reference: valley calibration is manual (Q2), b bins include 0.0, regime fingerprinting of external hosts must use Q5b, and merged-direction autocorrelation is diluted (bursty/poisson boundary). If a tenant result contradicts expectations, the Python pipeline is the ground truth for arbitration.
