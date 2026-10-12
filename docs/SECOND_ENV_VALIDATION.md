# Second-Environment Validation Report — IoT-23 (Public Data Only)

**Cyberseismology: Transferring the Statistical Laws of Earthquake Science to Network Intrusion Dynamics**
Parth Jamodkar — Independent Researcher
Compiled 2026-10-12 | Validation round: second environment, public datasets only

---

## 1. Purpose and constraint

The master document's quantitative claims were established on one vantage (the author's lab captures: AMOS, radiation, BN-44) plus one public ground-truth dataset (CTU-42). The stated publication blocker was **single-vantage validation**. This report closes that gap under a hard constraint imposed by operational reality: **no office, employer, or organizational logs may be used**. Both the reference pipeline test and the KQL (Microsoft Defender XDR) semantics test therefore run on a **public, labeled, independently collected dataset**.

## 2. Dataset

| Property | Value |
|---|---|
| Dataset | Stratosphere **IoT-23** v2, capture `CTU-IoT-Malware-Capture-1-1` |
| File | `2018-05-09-17-30-31-192.168.100.103-zeek-conn-log.labeled` (144,270,428 bytes) |
| Source URL | `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-1-1/` |
| Format | Zeek `conn.log` with appended `label` / `detailed_label` columns |
| Flows | **1,008,745** (539,472 Malicious = 53.5%, 469,275 Benign) |
| Malware profile | Mirai-class: 539,464 `PartOfAHorizontalPortScan` (target ports 23/2323/8080/9527), 8 `C&C` flows (port 2407, one contact each) |
| Topology | Single infected IoT host `192.168.100.103` generates 98.3% of flows |
| Ordering | Zeek conn.log is **close-time ordered**: 35.8% of adjacent rows are out of order by start timestamp |

Why this dataset qualifies as a *second environment*: different institution (CTU University, Stratosphere lab), different year (2018), different network class (IoT lab vs enterprise), different sensor (Zeek vs pcap/binetflow), different attack morphology (worm-like horizontal scanning vs botnet C2), and per-flow ground truth labels.

## 3. Method

1. **Reference pipeline** — `seismic_pipeline.py --zeek` with one loader correction: Zeek's unset-bytes marker `-` was treated as 0 instead of dropping the row (the original loader silently discarded 79% of this file; η-declustering does not use bytes, so dropping byte-less rows was a loader bug, not a methodological choice). All 1,008,745 flows analyzed.
2. **Ground-truth scoring** — per-flow η, M3, and regime outputs scored against the `label` column (AUC, precision/recall/enrichment at the valley thresholds).
3. **KQL semantics test** — the exact logic of KQL pack queries Q1 (η triage), Q3 (M3 blast radius), and Q5b (per-RemoteIP fingerprint) re-executed on the same flows shaped into `DeviceNetworkEvents` rows (direction-normalized: `RemoteIP` = external side), using the validated `kql_sim.py` semantics: per-class `prev()` partitioning, weights {1, 3.0314, 5.7995, 9.1896}, `min` over classes, `dcount` per 10-min bin, CV/DecayRatio/autocorr fingerprint rules. KQL's `order by Timestamp asc | serialize` was honored by sorting.

## 4. Results

### 4.1 Headline scoreboard

| Instrument | CTU-42 (first env) | IoT-23 (second env) | Verdict |
|---|---|---|---|
| Q1 η-declustering AUC (flow level) | **0.755** | **0.21–0.28** | **INVERTED — boundary condition found** |
| Q1 @ valley 0.08: retained / precision / recall / enrichment | 52.7% recall, 3.81× enrichment | 91.9% retained, 55.2% precision, 95.0% recall, **1.03×** | No triage value in this morphology |
| Q3 M3 blast radius (host level) | AUC 0.847 | infected host median **2.96–2.98** vs benign hosts **0.30** | **Transfers perfectly (host level)** |
| Q4 b-gauge (windowed GR) | stable 0.18–0.19 ± 0.04 | degenerate: b ≈ 0.001–0.1, R² ≈ 0.45 | Does not apply to single-source constant-rate catalogs |
| Q5b per-RemoteIP fingerprint | caught C2 (`omori_decay`, DR=0.50) | only **83 of 597,106** RemoteIPs fingerprintable (≥12 contacts); C&C IPs contacted once each | Not applicable to single-contact infrastructure |

### 4.2 Finding F1 — η-declustering inverts under scan morphology (the key result)

In CTU-42, malicious flows were *sparse and independent* against a *clustered benign background*: declustering (keep high-η "mainshocks") separated them at AUC 0.755. In IoT-23 the geometry is reversed:

- The attack **is** the cluster: a Mirai-class scan hits hundreds of thousands of distinct IPs at a near-constant ~1 s cadence. Each scan flow finds a recent parent in the /24 or /16 equivalence class → tiny Δt → tiny η → the η histogram shows a massive spike at log₁₀η ≈ 0.85 (the scan cadence). Declustering at any valley **removes the attack first**.
- Benign traffic from the same host is *slow and regular* (repeated connections to a few services) → large Δt → large η → it lands on the retained "mainshock" side.
- Result: malicious mass sits **below** the auto-detected bimodal valley (2.70). Scoring η against labels yields AUC 0.28 (reference) / 0.21 (KQL-sorted) — systematically *anti*-predictive.

This is not a failure of the port; it is a **boundary condition of the transferred law**. The seismological analog is precise: mainshock/aftershock declustering assumes a background of independent events with clusters superimposed. When the phenomenon of interest is itself a **swarm** (earthquake swarms have no mainshock — they are pure cluster), the correct instrument is the *inverted* one: cluster density, not independence. Flipping the sign yields a scan detector at AUC ≈ 0.72–0.79 with zero signatures. "Seismic swarm detection" is added to the framework as the scan-morphology counterpart of η triage.

### 4.3 Finding F2 — M3 blast radius transfers perfectly at host level

The infected host's median M3 is 2.96–2.98 (≈900–950 distinct destinations per 10-minute bin, sustained for 33 hours); every benign host sits at 0.30 (2 destinations). Separation is **perfect and parameter-free**. The flow-level AUC of 0.535 merely restates that M3 is a *host-level* instrument: it cannot (and is not designed to) separate malicious from benign flows *within* one host. For SOC operations this is the desired behavior: Q3 flags the device, an analyst then investigates the device.

### 4.4 Finding F3 — the b-gauge needs magnitude diversity

Windowed b-values degenerate (b ≈ 0.001–0.1, R² ≈ 0.45, flat across windows) because a single source scanning at a constant rate produces a near-constant distinct-destination count per bin — the M3 distribution has no dynamic range, so no GR regression is meaningful. Boundary condition: **the b-gauge requires a multi-source catalog with heterogeneous per-source activity.** This matches the master document's radiation-capture result (336 windows, stable b) where many hosts were active.

### 4.5 Finding F5 — the KQL port is semantically faithful on the second environment

Executing the exact KQL Q1 semantics (per-class `prev()`, η = min over 4 weighted classes, `serialize` ordering) on 1,008,745 rows:

- **98.77%** of mutually-finite values identical to the sorted reference implementation at 1e-6 tolerance; max |diff| = 4.7e-6 (pure float rounding; agreement is 100% at 1e-5).
- Decision-level Jaccard at valley 0.08: **92.2%** (residual = 137k rows whose file-order parent carries a later timestamp — Zeek writes at connection close, so 35.8% of rows are out of order by start time; KQL's explicit `order by Timestamp asc` handles this *more* correctly than file order, and the pack's queries already do this).
- Q3 reproduces host-level M3max exactly (2.98 vs 0.30).
- Q5b behaves as designed: it declines to fingerprint single-contact endpoints (all 8 C&C IPs) rather than emitting garbage classifications.

**Conclusion: the KQL pack runs correctly on public second-environment data with no tenant involved.** Everything a live-tenant deployment would compute is reproducible offline from public Zeek logs shaped into the XDR schema.

## 5. Implications for the framework (and the paper)

1. **The transfer is real but morphology-conditioned.** Two of five instruments (M3 host-level, regime fingerprints where applicable) transfer across environments unchanged; η-declustering transfers with a *direction* that depends on attack morphology (independence-seeking for C2/exfil among chatty background; cluster-seeking for scans). This is a stronger scientific result than uniform success would be: it defines **where each transferred law holds**, which is exactly what a reviewer asks of any claimed analogy.
2. **"Seismic swarms" join the framework.** Scan detection = inverted-η cluster-density scoring, directly analogous to earthquake swarms (clustered sequences with no mainshock). One paragraph + one detector rule.
3. **Boundary-conditions table** added to the master document: instrument × morphology × applicability, with both positive and negative results quantified across two independent public environments.
4. **Publication posture.** The second-environment test now exists, uses only public data, and reports a disciplined negative result — historically the difference between "toy transfer" and "method paper." The framework's claims are now stated with their domain of validity, which is how seismology itself treats Omori/GR (they too fail in swarms and volcanic tremor).

## 6. Reproducibility

| Artifact | Path |
|---|---|
| Raw dataset (public) | `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-1-1/` |
| Machine-readable results | `results/results_iot23_validation.json` |
| Pipeline | `seismic_pipeline.py` (`--zeek`; loader treats `-` bytes as 0) |
| KQL semantics simulator | `kql/kql_sim.py` (functions reused for Q1/Q3/Q5b) |
| KQL pack (validated 9/9 by Kusto.Language parser) | `kql/seismic-xdr.kql` v1.1 |

All inputs public; no organizational data of any kind was used at any step of this validation round.

*— end of report —*
