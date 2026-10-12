# Seismic Framework × Microsoft Defender XDR — KQL Integration Guide

**Version 1.0 · 2026-10-11 · Companion artifact: `seismic-xdr.kql` (7 queries)**
Scientific basis: Working Document v3.1 §8, §12 · Engineering basis: `seismic_pipeline.py` v1.0

---

## 1. The short answer

Yes — the framework ports to KQL because every instrument is built from three primitives that Advanced Hunting supports natively: **time-sorted windows** (`partition` + `prev()`), **distinct-count aggregation** (`dcount` + `bin`), and **manual OLS regression** (pure arithmetic in `summarize`). The XDR `DeviceNetworkEvents` table supplies everything the data model needs: `Timestamp`, `DeviceId/DeviceName`, `LocalIP`, `RemoteIP`, `RemotePort`, `Protocol`, `ActionType`, plus process attribution (`InitiatingProcessFileName`) that our pcap-based research never had — a free upgrade.

One honest caveat up front: **Advanced Hunting is a 30-day, 10-minute-timeout, 10k-row query service, not a stream processor.** The four instruments therefore split into two classes:

| Class | Instruments | Where they run |
|---|---|---|
| **Summarize-only** (cheap, full-fleet) | M3 blast radius (Q3), b-value gauge (Q4), combined score (Q6), NRT detection (Q7) | Advanced Hunting directly, up to 30 days |
| **Sort/partition** (expensive, scoped) | η triage queue (Q1), valley calibration (Q2), regime fingerprint (Q5) | AH scoped to ≤24h / one segment; full-catalog version stays in `seismic_pipeline.py` on exported logs |

## 2. Concept-to-schema mapping

| Framework concept (doc §) | XDR schema source | KQL mechanism |
|---|---|---|
| Flow record (§4) | `DeviceNetworkEvents` row, `ActionType in (ConnectionSuccess/Failed/Request)` | direct |
| Hierarchical distance D∈{1,2,3,4} (§12.1) | `RemoteIP`, `RemotePort` | `parse_ipv4(RemoteIP)` → `long`; D=3 key = `floor(ip/256)`, D=4 key = `floor(ip/65536)` |
| Backward Δt per equivalence class (§12.1) | `Timestamp` | `partition hint.strategy=native by <classkey> (order by Timestamp asc \| serialize \| extend dt = datetime_diff("millisecond", Timestamp, prev(Timestamp))/1000.0)` |
| η = Δt·D^1.6 (§12.1) | computed | row-wise `min_of` over the four classes |
| Valley / declustering threshold (§12.2) | computed | Q2 histogram → analyst picks valley; fallback 0.08 |
| M3 magnitude (§12.6) | `DeviceId`, `RemoteIP` | `summarize dcount(RemoteIP) by DeviceId, bin(Timestamp,10m)` → `log10(1+x)` |
| b-value gauge (§12.5) | M3 rows | `mv-expand` over magnitude bins → per-window OLS via `sum/sum(M*Y)` arithmetic |
| Regime fingerprint (§8) | per-device inter-arrivals | CV from `stdev/avg`; Omori-decay proxy = second-half/first-half event ratio |
| IOC scorer (demo only) | your TI feed | `ipv4_is_in_any_range(RemoteIP, ...)` or `externaldata`/watchlist join |

### What XDR adds that the research catalogs never had

- **Process attribution** (`InitiatingProcessFileName`, command line, hashes): every η-mainshock row immediately answers "which binary made this connection" — in the AMOS demo we had to infer that from timing alone.
- **`DeviceLogonEvents` and `DeviceProcessEvents`**: the graph-duality result (§12.6 — destination-anchored η misses cross-destination kill chains) can be addressed in XDR by running the same η machinery on *logon* events (lateral movement chains) and *process* events (execution cascades). Same math, different table. This is a concrete extension path the standalone sensor could not offer.

## 3. Deployment pattern

```
Defender XDR telemetry (native)
        │
        ▼
┌─────────────────────────────────────────────┐
│ ADVANCED HUNTING (this pack)                │
│  Q7 M3-spike  → Custom Detection (NRT, hourly)│
│  Q4 b-gauge   → Scheduled → Sentinel workbook │
│  Q1/Q6 queue  → Analyst hunting, daily        │
│  Q5 regimes   → Weekly source watchlist       │
└─────────────────────────────────────────────┘
        │ (optional, full-scale)
        ▼
Streaming export (Event Hubs) → seismic_pipeline.py
     for full-catalog η on >24h windows beyond AH limits
```

**Step-by-step:**

1. **Save Q0 as a function** (`SeismicFlows`) in Advanced Hunting → all other queries get shorter and consistent.
2. **Week 0 — silent:** run Q4 (b-gauge) over 7 days; run Q5 (regimes) over 24h; export results, no alerts.
3. **Week 1 — calibrate:** run Q2's η histogram on 3 different days; if bimodal, set `ValleyLogEta` at the valley, else keep 0.08. Record b mean/σ per environment.
4. **Week 2 — validate:** pick a past incident (or red-team exercise) inside the 30-day window; run Q1 for that day and confirm the intrusion surfaces in the top-100 queue. This is the exact test the AMOS demo passed (7/7 C2 flows, top 100 of 1,515).
5. **Go live:** Q7 as an NRT custom detection (severity Medium), Q4 as a Sentinel workbook chart with a ±2σ band, Q1/Q6 as the analysts' morning queue, Q5 weekly.

## 4. Service limits and how the pack respects them

| AH limit | Impact | Mitigation in the pack |
|---|---|---|
| 30-day lookback | No long baselines in AH | Baselines stored externally (Sentinel watchlist/CSV); Q4 chart is rolling 7d |
| 10-min timeout / CPU quota | Q1 (4 partition passes + 4 joins) is the only risky query | Scope Q1: 24h, ActionType filter, optionally `RemoteIPType=="Public"` or a single subnet via `ipv4_is_in_range`; comment markers included |
| 10k result rows | Full η catalog can't be dumped | Q1 returns `take 200` after ranking; Q5/Q6 aggregate to per-device rows |
| `dcount` is approximate (HLL) | M3 slightly fuzzy at scale | Use `count_distinct(RemoteIP)` in Q3 if exact counts matter more than speed |
| No Python plugin in AH | Bimodality valley can't be auto-detected like the Python pipeline | Q2 renders the histogram; analyst sets the valley (one-time calibration) |

**`partition` strategy note:** the pack uses `hint.strategy=native` (legacy strategy caps at 64 distinct keys — useless for IP partitioning). If your tenant's AH rejects native strategy, fall back to per-device or per-IP scoped queries using plain `order by … | serialize | extend … prev()` — the queries are written so this swap is mechanical.

## 5. Fidelity notes — KQL vs Python reference

| Instrument | Python (`seismic_pipeline.py`) | KQL pack | Verdict |
|---|---|---|---|
| η | 4-class latest-in-class, ms timestamps | identical math; AH timestamps are coarser (second-scale) | ranking reproduced; tiny η shifts at sub-second bursts |
| Valley | auto bimodality detection | analyst-picked from Q2 chart | acceptable (one-time calibration) |
| Regime | CV + lag-1 autocorr + log-log Omori slope | CV + half-life decay ratio | semantically same 4 classes; Omori proxy documented |
| M3 / b-value | exact distinct counts | `dcount` estimate (or exact on request) | equivalent |

The Python pipeline remains the **reference implementation**: if a KQL result looks wrong, export the same window to CSV/Zeek and re-run the Python tool — it is the ground truth for debugging the port.

## 6. SOC playbook deltas (adds to Deployment Guide §6)

- **P1 (morning triage)** becomes: run Q6, open the top device's row — `InitiatingProcessFileName` is right there; pivot to DeviceProcessEvents for the binary's tree.
- **P2 (regime flip)** runs weekly via Q5 export diffed against last week's export (Sentinel watchlist join).
- **P4 (post-incident)**: Q1 for the incident day + DeviceProcessEvents η (same query, different table) reconstructs both the network chain and the execution chain — the two-sided kill-chain view that validates/falsifies the graph-duality prediction with field data.

## 7. What this integration does NOT change

Every limitation from Working Document §16 and Deployment Guide §7 still applies: prioritization layer, not a blocking control; hand-designed distance metric; 52.7% declustering recall at the valley. KQL packaging changes the *delivery*, not the *evidence*. If anything, the XDR process attribution raises the ceiling: the next research iteration (learned η distance) can train on `(timing, addressing, process)` triples instead of timing alone.

## 8. Validation status (2026-10-11)

This pack has been machine-validated before delivery — see `KQL_VALIDATION_REPORT.md` for the full record:

- **Grammar + semantics:** all 9 queries pass `Microsoft.Azure.Kusto.Language` 12.4.1 `ParseAndAnalyze` against a mock XDR schema. (One real bug caught and fixed: `floor()` requires two arguments in current KQL.)
- **Ground-truth simulation:** the exact KQL logic was re-executed in Python on the AMOS capture in `DeviceNetworkEvents` shape. Reproduced exactly: M3 = 2.000 (victim) and C2 → `omori_decay` (via the new **Q5b** per-RemoteIP fingerprint — added because validation revealed XDR's endpoint-centric schema otherwise hides external hosts from regime fingerprinting).
- **Calibration is mandatory:** XDR's direction normalization shifts the η distribution down (fallback valley retains 7.5%, not 14%) — run Q2 and set `ValleyLogEta` from your own histogram before trusting Q1.
- **Not yet tested:** live-tenant execution, Q1 CPU cost at enterprise scale, AH timestamp granularity effects. Treat the first tenant run as Phase 0 of the Deployment Guide runbook.
