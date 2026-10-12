# Related Work & Novelty Positioning Brief — Cyberseismology
**2026-10-11 · for the paper "Cyberseismology: Transferring the Statistical Laws of Earthquake Science to Network Intrusion Dynamics" (P. Jamodkar)**
Source: scholar database searches (6 query batteries, 54 papers screened), cross-checked against web search. CSVs archived in /tmp/scholar/ (transient).

## 1. Closest prior art — MUST cite and differentiate

### Tier 1 — The physics-to-Internet transfer already exists (but NOT for security)
| Work | Venue / cites | What they did | Our differentiation |
|---|---|---|---|
| **Abe & Suzuki, "Omori's law in the Internet traffic" (2003)** | EPL, 37c | Omori law holds for aftershocks of "internetquakes" (traffic congestion cascades) | They study *congestion physics*; no security semantics, no labels, no detection |
| **Abe & Suzuki, "Gutenberg–Richter law for internetquakes" (2003)** | Physica A, 20c | GR law on internetquake sizes | Same — magnitude of congestion events, not attack severity; no b-as-diagnostic |
| **Abe & Suzuki, "Statistical similarities between internetquakes and earthquakes" (2004)** | Physica D, 23c | Unified statistical comparison | Conceptual precedent for transfer; zero operational content |
| **Pica Ciamarra, Coniglio et al., "Correlations and Omori law in spamming" (2008)** | EPL, 3c | Spam campaigns as mainshock-aftershock sequences, p≈1 | Closest *security-adjacent* work; spam only, no triage method, no GR/Bath/magnitude design |

**Positioning sentence (for the paper's intro):** "That Internet traffic and earthquakes share statistical structure has been known since Abe & Suzuki's internetquake studies (2003–2004) and Pica Ciamarra et al.'s spam analysis (2008). What has never been done is the *operational* transfer: casting network intrusion events as a seismic catalog and deriving working detection instruments — declustering, magnitude-frequency gauging, and regime classification — validated against ground-truth attack labels."

### Tier 2 — Point-process statistics of attacks (methodological neighbors)
| Work | Venue / cites | What they did | Our differentiation |
|---|---|---|---|
| **Zhan, Xu, Xu, "Characterizing honeypot-captured cyber attacks: Statistical framework" (2013)** | IEEE TIFS, 192c | First rigorous point-process framework for honeypot attack data | They model arrival statistics; no seismic laws, no declustering, no triage output |
| **Peng, Xu, Xu, Hu, "Modeling and predicting extreme cyber attack rates via marked point processes" (2017)** | JASA, 98c | Marked point processes predict extreme attack rates (VaR) | Aggregate rate prediction; no per-event independence score, no magnitude law |
| **Bessy-Roland, Boumezoued, Hillairet, "Multivariate Hawkes process for cyber insurance" (2021)** | IME, 107c | Hawkes processes model macro attack frequency for insurance pricing | Macro actuarial modeling; we do per-flow operational triage. Note: ETAS ≡ Hawkes branching — we should say this explicitly |
| **Boumezoued, Cherkaoui, Hillairet (2023–2025) series** | several, 2–11c | Hawkes with external excitation for cyber risk frequency | Same actuarial line |
| **HP-LSTM (2024)** | 7c | Hawkes+LSTM for DDoS stage prediction in-vehicle | ML hybrid for DDoS; different problem |

### Tier 3 — Tangential (cite lightly)
- Demydov et al. 2019, "Strategy of Informational Impacts in Cyberspace by Omori's Law" (IEEE conference, 1c) — information-operations strategy rhetoric using Omori.
- Rysavy & Sveda 2010 — mentions GR-respecting attack models in network security analysis (0c).
- Woo, "Calculating Catastrophe" (2011, 142c) — cyber-catastrophe modeling, earthquake-insurance analogy.
- Vasilomanolakis et al. 2015 (91c) — honeypot-driven incident monitoring (descriptive statistics, no point processes).

## 2. Unclaimed territory (novelty we can assert, with the caveat that formal peer review may surface more)

1. **Zaliapin nearest-neighbor declustering applied to network traffic/security** — 0 security hits in scholar search; all 54 screened declustering papers are seismology. **Claim: first application.**
2. **b-value as a network environment fingerprint / health gauge** — scholar query "b-value intrusion detection network" returned only seismology papers. **Claim: first.**
3. **Bath's law test in any cyber context** — no hits at all. Our *non-transfer* result (chains/stars, not hierarchies) is a genuine first.
4. **Magnitude design for intrusion events** (M1/M2/M3 evaluation, blast-radius M3 as severity axis) — no prior art found.
5. **Regime taxonomy** (omori_decay / periodic_beacon / bursty_cluster / poisson) as a host fingerprint with a real-world C2 catch — no prior art found.

## 3. Reviewer-objection forecast (write the paper to preempt these)

1. "Abe & Suzuki already did GR+Omori for Internet traffic" → §1 positioning sentence + a comparison table (theirs: congestion, unlabeled, descriptive; ours: intrusion, ground-truth-validated, operational).
2. "Hawkes/ETAS in cyber already exists" → that's actuarial frequency modeling (Tier 2); we cite it as motivation that self-exciting structure is real in cyber data.
3. "binned OLS b-values are biased" → fixed by the MLE + Mc upgrade (this sprint).
4. "single-vantage datasets" → acknowledged limitation; multi-environment roadmap.
5. "no ML baseline" → declustering compared against rate-z and novelty baselines in our validation; ML comparison = future work (say it).

## 4. Verdict for the user

**Novel: yes** — as an operational framework and validated transfer. **Not novel:** the abstract idea that networks and earthquakes rhyme (cite Abe & Suzuki prominently — doing so strengthens us, since their physics validates the premise while their papers contain nothing a SOC can run). The honest claim sentence: *"first validated operational transfer of the seismological statistical framework — declustering, magnitude-frequency law, Omori regimes, Bath analysis — to intrusion detection, with deployable artifacts."*
