# From Seismology to SOC: Real-World Deployment & Operations Guide

**Seismic-Intrusion Framework — Practical Companion to Working Document v3.1**
Version 1.0 · Compiled 2026-10-11

---

## 1. What you are actually deploying

This is not another detector. Everything in this guide follows from one design decision: the seismic framework is a **prioritization and situation-awareness layer** that sits *between* your telemetry and your analysts/ML stack. It consumes the flow data you already collect (Zeek, Suricata, NetFlow, firewall logs, pcap) and produces four instruments:

| Instrument | What it is | Validated performance | Seismic analog |
|---|---|---|---|
| **η triage queue** | Every flow scored by spatiotemporal "independence" η; repeating background collapses, anomalous chains rise | AUC 0.755 alone, 0.856 combined with M3 (CTU-42 ground truth); 3.8× botnet enrichment at 14% retention | Declustering: aftershocks removed so mainshocks become visible |
| **Regime fingerprint** | Per-source temporal classification: `omori_decay`, `periodic_beacon`, `bursty_cluster`, `poisson` | Recovered a real C2 endpoint's aftershock-decay signature from 12 flows (AMOS demo) | Volcanic vs tectonic vs swarm regimes |
| **b-value gauge** | Rolling fit of the magnitude-frequency law per time window | Stable at 0.188 ± 0.036 over 336 windows / 7 days (background radiation demo) | Stress gauge of a fault system |
| **M3 blast radius** | log₁₀(1 + distinct destinations per source per 10 min) | Best severity axis of all tested magnitudes (AUC 0.847) | Earthquake magnitude |

The core claim, validated in §12 of the working document: **timing structure alone — no payloads, no signatures, no threat intel — recovers intrusion structure.** In the AMOS Stealer demo, all 7 post-infection C2 flows surfaced in the top-100 triage queue of a 1,515-flow capture, and the C2 server was fingerprinted as an aftershock-decay process. That is what you are operationalizing.

## 2. Where it fits in a real security stack

```
SENSORS                SEISMIC LAYER                 CONSUMERS
─────────              ──────────────                ─────────
Zeek / Suricata  ──►   seismic_pipeline.py    ──►   SIEM (Elastic/Splunk)
NetFlow / sFlow        (batch or streaming)         SOAR playbooks
VPC flow logs    ──►   triage.csv                   Analyst workbench
pcap captures          sources.csv                  ML detection stack
                       report.json  ──►             Grafana dashboards
```

Three deployment principles:

1. **It is a lens, not a gate.** Never block on seismic scores. Declustering recall at the bimodality valley was 52.7% — that is a prioritization guarantee ("look here first"), not a detection guarantee. Use it to order analyst attention and to pre-filter data for expensive detectors (sandboxing, deep packet inspection, ML inference), where a 3.8× enrichment means 3.8× less compute for the same catch rate.
2. **It is cheapest where you already have flow data.** If you run Zeek or NetFlow, the marginal cost is a cron job and a few hundred MB of RAM. The reference implementation processed 428,223 flows (7 days) in ~2 minutes on a 4 GB VM.
3. **It degrades gracefully.** No model to retrain, no signatures to update, no labels required. The only learned parameter is the η valley, and it is re-estimated from the data itself on every run (with a fixed fallback).

## 3. Reference architectures

### 3.1 Tier 1 — Forensic / IR workstation (zero infrastructure)

The pipeline as-delivered. An incident responder drops a pcap or Zeek `conn.log` on the tool:

```bash
python3 seismic_pipeline.py incident.pcap -o case42 --iocs known_bad.txt --top 200
```

Outputs: a ranked triage queue (CSV, opens in Excel), per-source regime fingerprints, a JSON run summary. This is the mode we demoed on AMOS and radiation data. Use for: post-incident forensics, threat-hunting over historical captures, purple-team validation.

### 3.2 Tier 2 — Scheduled batch (daily/hourly SOC feed)

Zeek (or your existing sensor) writes conn logs; a cron job runs the pipeline every N hours and ships outputs to the SIEM:

```bash
# /etc/cron.hourly/seismic
zeek -r /logs/capture.pcap /usr/local/zeek/share/zeek/base/protocols/conn
python3 seismic_pipeline.py /logs/conn.log --zeek -o /out/seismic_$(date +%s)
curl -X POST $SIEM_HEC -H "Authorization: Splunk $TOKEN" -d @/out/seismic_*_report.json
```

- `triage.csv` → SIEM indexed as `seismic_triage` events; analyst dashboard = "top-100 queue."
- `sources.csv` → indexed as `seismic_regimes`; alert on any source flipping to `omori_decay` or `periodic_beacon`.
- `report.json` → b-value time series into Grafana; alert on |Δb| > 2σ of the environment baseline (we measured σ ≈ 0.036 on quiet background; calibrate your own, §5).

Sizing: 1 vCPU / 4 GB handles ~400k flows per run comfortably. A busy /24 enterprise segment typically generates 50–500k flows/hour, so hourly batches fit; busier sensors → Tier 3.

### 3.3 Tier 3 — Streaming (high-volume sensors)

For >1M flows/hour, run the stages as a microservice chain instead of the batch script:

- **Flow aggregator** (your existing Zeek/Kafka pipeline) → 5-tuple flow records.
- **η scorer**: the algorithm is O(n) with tiny state (4 dict entries per flow: last-seen per class) — it ports directly to Flink/Spark Streaming or a Go service. State is just "latest flow per (dst,dport), per dst, per /24, per /16," so it is trivially partitioned by destination.
- **Regime classifier + M3**: per-source sliding windows in a stream processor; emit classifications on window close.
- **b-value gauge**: per-window magnitude histograms → one OLS fit per window. Costs nothing.

The science does not change; only the plumbing. The Python prototype is the reference implementation against which a streaming port is validated (same η on the same input, bit-for-bit).

## 4. Operating the four instruments

### 4.1 The triage queue (daily driver)

Analysts start their shift at the top of the queue, not in the alert flood. Each row: src → dst:port, time, log₁₀η, bytes. Reading guide:

- **High η (top of queue)** = flow that does not belong to any recent repetition pattern. Isolated first-contacts, rare port touches, one-off exfil bursts. In the AMOS demo, the C2 join appeared at rank 13 of 1,515.
- **Low η (declustered away)** = flows that repeat a recent pattern (the same destination, subnet, or port class). This is where 86% of a normal catalog lives; suppressing it is the point.
- **Operating the threshold**: the auto-valley detection finds the bimodality split; if your catalog is not bimodal (uniform attack-free telescope traffic), the tool falls back to 0.08 (the CTU-42 ground-truth valley). You can pin it with `--valley` once calibrated.

### 4.2 Regime fingerprints (source watchlist)

Per-source classes and what to do with them:

| Class | Meaning | Analyst action |
|---|---|---|
| `omori_decay` | Rate decaying like an aftershock sequence — a *triggered* process winding down (post-exploitation callbacks, exfil tails) | Highest priority. Find the triggering event (the "mainshock"): the highest-η flow from/to that host shortly before the decay started |
| `periodic_beacon` | Low jitter inter-arrivals | Classic beacon check; cross-ref with M3 — a beacon touching many destinations is scanning, one destination is C2 |
| `bursty_cluster` | Clustered bursts, positive memory | Campaign/scan activity; check whether bursts align with business schedules (backup windows look exactly like this — whitelist) |
| `poisson` | Memoryless background | Ignore unless M3 is extreme |

Rule of thumb from the demos: **an `omori_decay` classification on a host with few flows is the strongest single signal this framework produces** — the AMOS C2 had 12 flows and still stood out.

### 4.3 The b-value gauge (health of the whole environment)

Chart the per-window b-value. Interpretation:

- **Stable baseline** (ours: 0.188 ± 0.036 on background radiation): normal environment. Alarm threshold = baseline ± 2σ, calibrated per sensor over its first week.
- **Sudden b drop** = magnitude distribution shifted toward large events — many sources touching many destinations. Consistent with a worm-like spread or coordinated scan campaign entering the view.
- **Sudden b rise** = distribution dominated by small events — quiet, or a single low-and-slow actor.

This is a *population-level* instrument: it will not name the attacker, but it is essentially free to compute and answers "is today different from every other day?" in one number. In seismology, b-value drops precede mainshocks; whether the precursory version holds in cyber is an open research question (§17 of the working document) — operationally, treat it as a drift alarm, not a forecast.

### 4.4 M3 blast radius (severity axis)

Use M3 wherever you currently use "bytes transferred" as a severity proxy — it strictly dominates it (AUC 0.847 vs 0.335 on ground truth). Byte counts measure *volume*; M3 measures *reach*. A 200 MB download from one CDN node is noise; a host touching 100 distinct destinations in 10 minutes (M3 = 2.0, the AMOS victim at infection time) is a story.

## 5. Calibration runbook (first two weeks)

Do not tune against theory; tune against your own wire.

1. **Week 0 — silent mode.** Deploy, collect outputs, alert on nothing.
2. **Week 1 — establish baselines.** Compute your environment's b-value mean/σ per sensor; record the auto-valley per run (expect it to wander; if it collapses to the fallback every time, your traffic may lack a repeating-background population — normal for small captures).
3. **Replay known incidents.** Take pcaps of past confirmed incidents (or the AMOS capture from the working document) and verify the intrusion surfaces in the top-N queue. If it does not, check sensor vantage first (§5.1), then η distance design (a known limitation).
4. **Set thresholds.** Pick the triage queue depth your team can actually clear (a 100-row queue ≈ 1 analyst-hour). Set b-value alarms at ±2σ. Whitelist business-schedule bursts from regime alerts.
5. **Go live with playbooks** (§6).

### 5.1 Vantage requirements

The framework sees *repetition and causality in time*, which needs:

- **Both directions** of a conversation ideally (η is destination-anchored; unidirectional flow logs still work but halve the resolution).
- **Timestamps to ~1 ms** (Zeek/pcap fine; 1-minute NetFlow bins blur the aftershock mode of the η distribution — you will still get b-values and M3, but declustering degrades).
- **Coverage of the segment you care about.** A sensor on the internet border will fingerprint scanning fine but cannot see lateral east-west chains; an internal TAP sees chains but not the infection's first contact. The working document's "graph duality" result (§12.6) implies the two views are complementary, not redundant.

## 6. SOC playbooks

**P1 — Morning triage.** Open `seismic_triage`, top 100. For each unfamiliar dst in high-η rows: check `seismic_regimes` for the src (is the source decaying? beaconing?), then M3 (blast radius?), then your TI/EDR. The seismic layer's job ends at "this deserves 10 minutes of your time."

**P2 — Regime-flip alert.** A host that was `poisson` for weeks becomes `omori_decay` or `periodic_beacon` → open an investigation: find the highest-η flow involving that host in the previous 24 h (the candidate trigger), then walk the η parent tree (the prototype already computes parents — the forest is the candidate causal chain).

**P3 — b-value excursion.** Gauge breaches ±2σ → check M3-heavy sources in that window, check regime census for a spike in `bursty_cluster` sources, correlate with change windows (a new app deployment looks identical to a scan campaign to this instrument — §7 honesty applies).

**P4 — Post-incident.** During IR, run Tier 1 on captured traffic around the incident window. Deliverable for the report: the η-cluster tree of the intrusion (root = initial contact, descendants = causal chain), the regime timeline of involved hosts, and the b-value track across the incident. This is incident documentation nobody else can currently produce.

## 7. Honest limitations (read before deploying)

1. **Not a blocking control.** 52.7% recall at the validated operating point. It prioritizes; your EDR/NDR signatures decide.
2. **Hand-designed distance metric.** The η network distance (dstIP/dport//24//16 hierarchy) is hand-built. Environments with heavy CDN/anycast traffic will need the fallback valley or a custom distance (learning the metric from data is on the research roadmap).
3. **Vantage and window dependence.** M3 values depend on the 10-min window and sensor placement; compare M3 only within the same deployment.
4. **Encrypted traffic.** The framework uses only timing + addressing, so TLS is irrelevant to it — an advantage — but it also means it can never tell you *what* was exfiltrated.
5. **Small catalogs.** Under ~1,000 flows the valley auto-detection and b-fits get noisy; the AMOS demo (1,515 flows) is near the practical floor for the full instrument set.

## 8. Integration recipes (copy-paste starters)

**Elastic:** `triage.csv` → Filebeat CSV module → index `seismic-triage-*`; dashboard: table sorted by `log10_eta` desc, filter `ioc_hit: 1` first.

**Splunk:** monitor the output dir (`[monitor:///out/seismic]`, `sourcetype=csv`); alert search: `sourcetype=seismic_sources regime IN (omori_decay, periodic_beacon) | stats count by src`.

**Grafana (b-gauge):** `report.json → gr_windows[]` → push to InfluxDB/Prometheus via a 20-line exporter; panel = b-value line with ±2σ band.

**SOAR (P2 automation):** on regime-flip, auto-enrich the src host (EDR isolate candidate, AD lockout candidate — *recommendation only*, human approves).

## 9. Rollout roadmap

| Phase | Scope | Exit criteria |
|---|---|---|
| 0 — Forensic | Tier 1 on IR cases only | 2 real cases where the queue ranked the intrusion top-100 |
| 1 — Silent batch | Tier 2 hourly, one sensor | Baselines stable; zero business-hours false alarms in week 2 |
| 2 — Assisted triage | Analysts start shift from the queue | Measured: time-to-first-triage-action down; catch rate of expensive tools unchanged at reduced throughput |
| 3 — Streaming + gauges | Tier 3, b-value alarming, SOAR hooks | b-alarm precision acceptable to the team; runbooks written |

## 10. What to send back to research

Two field measurements would close the biggest open loops (§17 of the working document):

1. **Per-environment η valleys and b-baselines** (one line per sensor per week) — tests whether b really fingerprints environments across organizations, not just across our catalogs.
2. **Confirmed-incident replays**: does your incident's causal chain appear as one η-cluster? The graph-duality prediction says destination-anchored η will fragment cross-destination kill chains; field data decides whether source-anchored η recovers them.

---

*Reference implementation: `seismic_pipeline.py` v1.0. Scientific basis: Seismic-Intrusion-Framework-Working-Document v3.1 (declustering §12.1–12.4, pooled magnitude law §12.5, magnitude design §12.6, limitations §16, open problems §17). Demo evidence: PIPELINE_DEMO_REPORT.md.*
