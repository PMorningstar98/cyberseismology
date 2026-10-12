# Cyberseismology

**Transferring the statistical laws of earthquake science to network intrusion dynamics.**

Parth Jamodkar — Independent Researcher

SOC analysts and seismologists face the same problem shape: a massive, bursty catalog of events where a tiny fraction matters — and the structure of the noise is itself informative. This repository operationalizes that insight: **four earthquake-science instruments, ported to network telemetry, validated against public ground truth, and shipped as runnable artifacts.**

| Instrument | Earthquake analog | What it does | Validated result |
|---|---|---|---|
| **η triage queue** | Zaliapin nearest-neighbor declustering | Scores every flow by spatiotemporal independence; background repetition collapses, anomalous chains rise | AUC **0.755** on CTU-42 botnet ground truth; 3.8× enrichment, 7.2× volume reduction — **zero signatures** |
| **M3 blast radius** | Earthquake magnitude | log₁₀(1 + distinct destinations per host per 10 min) | AUC **0.847** — dominates byte-volume (0.335); separates infected IoT host (2.98) from benign (0.30) on IoT-23 |
| **b-value gauge** | Gutenberg–Richter law | Rolling magnitude-frequency slope of the environment | Stable 0.188 ± 0.036 over 336 windows / 7 days (population health monitor) |
| **Regime fingerprints** | Omori aftershock law + seismic regimes | Classifies sources: `omori_decay` / `periodic_beacon` / `bursty_cluster` / `poisson` | Recovered a real C2 endpoint's aftershock-decay signature from just **12 flows** (AMOS Stealer capture) |

**Boundary conditions, honestly reported** (what makes this a method, not a metaphor): on a second, independently collected dataset (IoT-23 Mirai-class scan), η-declustering *inverts* (AUC 0.21–0.28) because the attack **is** the cluster — exactly the situation seismology handles with **earthquake-swarm detection**, which this toolkit provides as the inverted-η mirror (AUC ~0.72–0.79). The full domain-of-validity map is in `docs/SECOND_ENV_VALIDATION.md`.

## Quickstart (60 seconds)

```bash
pip install numpy   # the only dependency

# pcap in -> triage queue out
python3 seismic_pipeline.py capture.pcap -o run --top 100

# Zeek conn log
python3 seismic_pipeline.py conn.log --zeek -o run
```

Outputs per run: `<out>_triage.csv` (priority queue), `<out>_sources.csv` (per-source regime + M3), `<out>_report.json` (run summary). Memory-safe to ~3M flows on 4 GB RAM; ~2 min for 428k flows.

## Repository layout

```
seismic_pipeline.py        Zero-dependency reference pipeline (pcap / Zeek TSV / Zeek JSON)
kql/seismic-xdr.kql        Microsoft Defender XDR Advanced Hunting pack — 9 validated KQL queries
kql/kql_sim.py             Offline simulator: executes the EXACT KQL semantics without a tenant
docs/                      Validation reports, deployment guides, live-tenant manual
results/                   Machine-readable results (declustering, GR, MLE, second environment)
```

## Validate it yourself (public data only — no organizational logs needed)

```bash
# 1. Download public ground truth (CTU-42, ~700 MB)
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13/CTU-13-Dataset/capture20110810/capture20110810.binetflow.2format
# (or any capture from https://mcfp.felk.cvut.cz/publicDatasets/)

# 2. Run the pipeline, score against the inline labels
python3 seismic_pipeline.py capture20110810.binetflow.2format --zeek -o ctu42
```

Expected: η bimodality with the botnet overlaying the independent mode; botnet recall ~52.7% at the valley with 3.8× enrichment. The IoT-23 second-environment protocol and exact numbers: `docs/SECOND_ENV_VALIDATION.md`.

## The KQL pack (Defender XDR / Advanced Hunting)

`kql/seismic-xdr.kql` ports all instruments to Microsoft Defender XDR's `DeviceNetworkEvents` schema — including an NRT-compliant custom detection (M3 spike) and a per-RemoteIP variant (Q5b) that fingerprints external C2 hosts, which the endpoint-centric schema would otherwise hide. All 9 queries pass Microsoft's official Kusto parser (`Microsoft.Azure.Kusto.Language`), and the exact KQL logic was re-executed against ground truth: **98.77% value identity with the reference implementation on 1M flows**. See `docs/KQL_VALIDATION_REPORT.md` and `docs/LIVE_TENANT_MANUAL.md` for installation and a 14-day calibration runbook.

## Research record

- Working paper: *Cyberseismology: Transferring the Statistical Laws of Earthquake Science to Network Intrusion Dynamics* (v3.3) — preprint forthcoming on arXiv (cs.CR, cross-list physics.soc-ph).
- Prior art positioned, not ignored: Abe & Suzuki's internetquakes (2003–04), spam-Omori (2008), honeypot point processes (2013, 2017), Hawkes cyber-insurance line — see `docs/RELATED_WORK_BRIEF.md` for the 5 unclaimed claims.
- Reproducibility: every quantitative claim in the paper traces to `results/*.json` and public datasets (CTU-42, IoT-23, Stratosphere).

## License

MIT (code) · CC-BY-4.0 (documents). Datasets are property of their respective publishers (Stratosphere/CTU) and are not redistributed here.
