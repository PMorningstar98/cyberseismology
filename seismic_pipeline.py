#!/usr/bin/env python3
"""
seismic_pipeline.py — Seismic Intrusion Triage Prototype (v1.0)
================================================================
Reference implementation of the Seismic-Intrusion Framework
(Working Document v3.1, Sections 4, 12).

Input : pcap (libpcap, Ethernet/IPv4, TCP+UDP)  OR  Zeek conn log (TSV or JSON-lines)
Output: 1. <out>_triage.csv   — eta-declustered triage queue, highest-priority first
        2. <out>_sources.csv  — per-source regime fingerprint + M3 blast-radius severity
        3. <out>_report.json  — run summary: eta valley, decluster stats, b-values, verdicts

Pipeline stages
  S1  flow extraction        5-tuple aggregation, anchored at first-packet (SYN) time
  S2  eta scoring            Zaliapin nearest-neighbour score  eta = dt_backward * D^1.6
                             hierarchical distance D in {1,2,3,4}
                             (1 same dstIP+dport, 2 same dstIP, 3 same /24, 4 same /16)
  S3  declustering           data-driven bimodality valley on log10 eta
                             (fallback: 0.08, the CTU-42 ground-truth valley)
  S4  regime fingerprint     per-source inter-arrival statistics -> 4-signature class
                             (omori_decay / periodic_beacon / bursty_cluster / poisson)
  S5  magnitude & b-value    M3 = log10(1 + distinct destinations per src per 10-min bin);
                             binned GR fit  log10 N(>=m) = a - b*m  per 30-min window

Only stdlib + numpy required. Memory-safe (array primitives) up to ~3M flows on 4GB RAM.

Usage:
  python3 seismic_pipeline.py INPUT.pcap            [-o out_prefix] [--valley X]
  python3 seismic_pipeline.py conn.log --zeek       [-o out_prefix]
  python3 seismic_pipeline.py conn.json --zeek-json [-o out_prefix]
"""
import sys, os, json, math, struct, argparse, ipaddress
from array import array
from collections import defaultdict

import numpy as np

# ----------------------------------------------------------------------------- S1: input
def ip2u32(s):
    try:
        return int(ipaddress.IPv4Address(s))
    except Exception:
        return 0

def load_pcap(path, max_flows=None):
    """Pure-python libpcap reader. Ethernet linktype, IPv4, TCP/UDP.
    Returns arrays: ts(float s), src,dst (u32), dport, bytes; aggregated by 5-tuple."""
    with open(path, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError('not a pcap file')
        magic = gh[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            endian, nano = '<', False
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian, nano = '>', False
        elif magic == b'\x4d\x3c\xb2\xa1':
            endian, nano = '<', True
        elif magic == b'\xa1\xb2\x3c\x4d':
            endian, nano = '>', True
        else:
            raise ValueError('unsupported pcap magic %r' % magic)
        network = struct.unpack(endian + 'I', gh[20:24])[0]
        if network != 1:
            raise ValueError('only Ethernet linktype supported (got %d)' % network)
        div = 1e9 if nano else 1e6
        # first pass: aggregate packets into flows keyed by 5-tuple
        flows = {}
        order = []
        n_pkt = 0
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_frac, incl, orig = struct.unpack(endian + 'IIII', ph)
            pkt = f.read(incl)
            if len(pkt) < incl:
                break
            n_pkt += 1
            if len(pkt) < 34:
                continue
            eth = struct.unpack('!H', pkt[12:14])[0]
            off = 14
            if eth == 0x8100:  # VLAN
                if len(pkt) < 38: continue
                eth = struct.unpack('!H', pkt[16:18])[0]
                off = 18
            if eth != 0x0800:
                continue
            ip = pkt[off:off + 20]
            if len(ip) < 20 or (ip[0] >> 4) != 4:
                continue
            ihl = (ip[0] & 0x0F) * 4
            proto = ip[9]
            if proto not in (6, 17):
                continue
            total_len = struct.unpack('!H', ip[2:4])[0]
            src = struct.unpack('!I', ip[12:16])[0]
            dst = struct.unpack('!I', ip[16:20])[0]
            l4 = pkt[off + ihl: off + ihl + 4]
            if len(l4) < 4:
                continue
            sport, dport = struct.unpack('!HH', l4)
            t = ts_sec + ts_frac / div
            key = (src, dst, sport, dport, proto)
            fl = flows.get(key)
            if fl is None:
                flows[key] = [t, total_len]
                order.append(key)
            else:
                if t < fl[0]:
                    fl[0] = t
                fl[1] += total_len
            if max_flows and len(flows) >= max_flows:
                break
        n = len(flows)
        ts = array('d', (0.0,) * n)
        srca = array('I', (0,) * n)
        dsta = array('I', (0,) * n)
        dpt = array('I', (0,) * n)
        byt = array('I', (0,) * n)
        for i, key in enumerate(order):
            s, d, sp, dp, pr = key
            fl = flows[key]
            ts[i] = fl[0]; srca[i] = s; dsta[i] = d; dpt[i] = dp; byt[i] = fl[1]
        # sort by time
        idx = sorted(range(n), key=lambda i: ts[i])
        ts = array('d', (ts[i] for i in idx))
        srca = array('I', (srca[i] for i in idx))
        dsta = array('I', (dsta[i] for i in idx))
        dpt = array('I', (dpt[i] for i in idx))
        byt = array('I', (byt[i] for i in idx))
        return ts, srca, dsta, dpt, byt, n_pkt

def load_zeek_tsv(path):
    """Zeek conn.log TSV with #fields header."""
    ts = array('d'); srca = array('I'); dsta = array('I')
    dpt = array('I'); byt = array('I')
    fields = None
    n_pkt = 0
    with open(path, 'r', errors='replace') as f:
        for line in f:
            if line.startswith('#fields'):
                fields = line.rstrip('\n').split('\t')[1:]
                continue
            if line.startswith('#') or not line.strip():
                continue
            if fields is None:
                raise ValueError('no #fields header found')
            p = line.rstrip('\n').split('\t')
            row = dict(zip(fields, p))
            try:
                t = float(row['ts'])
                s = ip2u32(row['id.orig_h']); d = ip2u32(row['id.resp_h'])
                dp = int(row.get('id.resp_p', '0') or 0)
                b = int(float(row.get('orig_bytes', '0') or 0)) + int(float(row.get('resp_bytes', '0') or 0))
            except Exception:
                continue
            ts.append(t); srca.append(s); dsta.append(d); dpt.append(dp); byt.append(max(b, 1))
            n_pkt += 1
    return ts, srca, dsta, dpt, byt, n_pkt

def load_zeek_json(path):
    ts = array('d'); srca = array('I'); dsta = array('I')
    dpt = array('I'); byt = array('I')
    n_pkt = 0
    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                t = float(r['ts'])
                s = ip2u32(r['id.orig_h']); d = ip2u32(r['id.resp_h'])
                dp = int(r.get('id.resp_p', 0) or 0)
                b = int(float(r.get('orig_bytes', 0) or 0)) + int(float(r.get('resp_bytes', 0) or 0))
            except Exception:
                continue
            ts.append(t); srca.append(s); dsta.append(d); dpt.append(dp); byt.append(max(b, 1))
            n_pkt += 1
    return ts, srca, dsta, dpt, byt, n_pkt

# ---------------------------------------------------------------- S2: eta scoring
def eta_scores(ts, dst, dpt, exponent=1.6):
    """Zaliapin-style nearest-neighbour score, destination-anchored.
    eta = dt_backward * D^exponent, D = hierarchical network distance to the
    most recent prior flow in the tightest shared equivalence class.
    O(n) via latest-in-class bookkeeping (4 classes per flow).
    Returns log10 eta array (np.float64) and parent index array (-1 = no parent)."""
    n = len(ts)
    log_eta = np.full(n, np.nan)
    parent = np.full(n, -1, dtype=np.int64)
    last_dp = {}    # (dst, dport) -> (index, ts)
    last_ip = {}    # dst -> (index, ts)
    last_24 = {}    # dst >> 8
    last_16 = {}    # dst >> 16
    INF = 1e18
    for i in range(n):
        t = ts[i]; d = dst[i]; p = dpt[i]
        # eta = dt * D^exp; pick minimum over the 4 equivalence classes
        best_eta = INF; best_par = -1
        for cand, D in ((last_dp.get((d, p)), 1), (last_ip.get(d), 2),
                        (last_24.get(d >> 8), 3), (last_16.get(d >> 16), 4)):
            if cand is None:
                continue
            dt = t - cand[1]
            if dt <= 0:
                dt = 1e-6
            e = dt * (D ** exponent)
            if e < best_eta:
                best_eta = e; best_par = cand[0]
        if best_par >= 0 and best_eta < INF:
            log_eta[i] = math.log10(max(best_eta, 1e-12))
            parent[i] = best_par
        # update classes
        last_dp[(d, p)] = (i, t)
        last_ip[d] = (i, t)
        last_24[d >> 8] = (i, t)
        last_16[d >> 16] = (i, t)
    return log_eta, parent

def find_valley(log_eta, default=0.08):
    """Data-driven bimodality valley on log10 eta.
    Find the two dominant modes, take the histogram minimum between them."""
    x = log_eta[np.isfinite(log_eta)]
    if len(x) < 100:
        return default, False
    lo, hi = np.percentile(x, [0.5, 99.5])
    hist, edges = np.histogram(x, bins=120, range=(lo, hi), density=True)
    # smooth
    k = np.ones(5) / 5.0
    h = np.convolve(hist, k, mode='same')
    centers = 0.5 * (edges[:-1] + edges[1:])
    # two modes: global max, then max on the opposite side of the median gap
    i1 = int(np.argmax(h))
    # suppress neighbourhood of first mode
    mask = np.abs(centers - centers[i1]) > 1.0
    if not mask.any():
        return default, False
    i2 = int(np.argmax(np.where(mask, h, -1)))
    a, b = min(i1, i2), max(i1, i2)
    if b - a < 5:
        return default, False
    iv = a + int(np.argmin(h[a:b + 1]))
    valley = float(centers[iv])
    # sanity: modes must be meaningfully separated
    if abs(centers[i2] - centers[i1]) < 1.5:
        return default, False
    return valley, True

# ------------------------------------------------------- S4: regime fingerprint
def regime_fingerprint(times):
    """Classify a source's inter-arrival pattern into one of 4 signatures.
    Returns (label, cv, lag1_autocorr, omori_p, n)."""
    t = np.sort(np.asarray(times, dtype=float))
    n = len(t)
    if n < 8:
        return ('insufficient', np.nan, np.nan, np.nan, n)
    iat = np.diff(t)
    iat = iat[iat > 0]
    if len(iat) < 7:
        return ('insufficient', np.nan, np.nan, np.nan, n)
    mean = iat.mean()
    cv = float(iat.std() / mean) if mean > 0 else np.nan
    x = iat[:-1]; y = iat[1:]
    if x.std() > 0 and y.std() > 0:
        r = float(np.corrcoef(x, y)[0, 1])
    else:
        r = 0.0
    # Omori decay: aftershock-like decay means the rate DECREASES with time,
    # i.e. inter-arrival times INCREASE with time since the first event.
    # Fit slope of log(iat) vs log(time since first event); p > 0 => decaying cascade.
    iat2 = np.diff(t)
    tt = t[1:] - t[0]
    ok = (tt > 0) & (iat2 > 0)
    if ok.sum() >= 5:
        omori_p = float(np.polyfit(np.log(tt[ok]), np.log(iat2[ok]), 1)[0])
    else:
        omori_p = np.nan
    # classification rules (calibrated on CTU-42/bn44/AMOS/radiation, doc Section 8-12)
    if cv < 0.5 and abs(r) < 0.3:
        label = 'periodic_beacon'
    elif omori_p == omori_p and omori_p > 0.35 and cv > 0.9:
        label = 'omori_decay'       # aftershock-like cascade (attack chain)
    elif cv > 1.3 and r > 0.15:
        label = 'bursty_cluster'    # clustered bursts (scan/campaign)
    else:
        label = 'poisson'           # background-like
    return (label, cv, r, omori_p, n)

# ------------------------------------------------------- S5: magnitude & GR fit
def m3_magnitudes(ts, src, dst, window=600.0):
    """M3 blast radius: log10(1 + distinct destinations per source per window).
    Returns per-flow M3 array."""
    n = len(ts)
    m3 = np.zeros(n)
    seen = {}   # (src, bin) -> set of dst
    bins = (ts / window).astype(np.int64) if isinstance(ts, np.ndarray) else None
    if bins is None:
        bins = np.array([int(t / window) for t in ts], dtype=np.int64)
    sets = defaultdict(set)
    for i in range(n):
        sets[(src[i], bins[i])].add(dst[i])
    for i in range(n):
        m3[i] = math.log10(1 + len(sets[(src[i], bins[i])]))
    return m3

def binned_gr(mags, mlo=0.0, mhi=None, step=0.25):
    """Binned OLS fit of log10 N(>=m) = a - b*m. Returns (b, a, r2, n_pts)."""
    m = np.asarray(mags, dtype=float)
    m = m[np.isfinite(m)]
    if len(m) < 30:
        return (np.nan, np.nan, np.nan, 0)
    if mhi is None:
        mhi = np.percentile(m, 99)
    edges = np.arange(mlo, mhi + 1e-9, step)
    if len(edges) < 4:
        return (np.nan, np.nan, np.nan, 0)
    msort = np.sort(m)
    xs, ys = [], []
    for e in edges:
        c = len(m) - np.searchsorted(msort, e)
        if c > 0:
            xs.append(e); ys.append(math.log10(c))
    if len(xs) < 3:
        return (np.nan, np.nan, np.nan, 0)
    xs = np.array(xs); ys = np.array(ys)
    A = np.vstack([xs, np.ones_like(xs)]).T
    coef, res, *_ = np.linalg.lstsq(A, ys, rcond=None)
    pred = A @ coef
    ss_res = float(((ys - pred) ** 2).sum())
    ss_tot = float(((ys - ys.mean()) ** 2).sum())
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else np.nan
    return (-float(coef[0]), float(coef[1]), r2, len(xs))

# ------------------------------------------------------------------ report / main
def fmt_ip(u):
    return str(ipaddress.IPv4Address(u))

def load_iocs(path):
    """One IP or CIDR per line (comments with # allowed). Returns list of networks."""
    nets = []
    with open(path, errors='replace') as f:
        for line in f:
            line = line.split('#')[0].strip()
            if not line:
                continue
            # extract first token that looks like an IP/CIDR (IOC files are often messy)
            for tok in line.replace(',', ' ').split():
                try:
                    nets.append(ipaddress.IPv4Network(tok, strict=False))
                    break
                except Exception:
                    continue
    return nets

def ioc_hit(u32, nets):
    if not nets:
        return False
    a = ipaddress.IPv4Address(u32)
    for nt in nets:
        if a in nt:
            return True
    return False

def run(args):
    print('[S1] loading %s ...' % args.input, flush=True)
    if args.zeek:
        ts, src, dst, dpt, byt, n_pkt = load_zeek_tsv(args.input)
    elif args.zeek_json:
        ts, src, dst, dpt, byt, n_pkt = load_zeek_json(args.input)
    else:
        ts, src, dst, dpt, byt, n_pkt = load_pcap(args.input, max_flows=args.max_flows)
    n = len(ts)
    dur = (ts[-1] - ts[0]) if n > 1 else 0.0
    print('     %d packets -> %d flows over %.1f min' % (n_pkt, n, dur / 60.0), flush=True)
    if n < 20:
        print('too few flows; aborting')
        return
    nets = load_iocs(args.iocs) if args.iocs else []
    if nets:
        print('     %d IOC networks loaded' % len(nets), flush=True)

    print('[S2] eta scoring ...', flush=True)
    log_eta, parent = eta_scores(ts, dst, dpt)
    finite = np.isfinite(log_eta)

    print('[S3] declustering ...', flush=True)
    if args.valley is not None:
        valley, auto = args.valley, False
    else:
        valley, auto = find_valley(log_eta)
    residual = finite & (log_eta >= valley)     # independent / clustered side
    background = finite & (log_eta < valley)    # repeating background
    print('     valley log10 eta = %.2f (%s)' % (valley, 'auto' if auto else 'given/default'), flush=True)
    print('     retained %d (%.1f%%), declustered %d (%.1f%%)' % (
        residual.sum(), 100.0 * residual.sum() / n,
        background.sum(), 100.0 * background.sum() / n), flush=True)

    # triage queue: residual flows, most independent (largest eta) first — these are the
    # "mainshock candidates"; plus small-eta flows are summarized away as aftershocks.
    order = np.argsort(-np.where(residual, log_eta, -np.inf))
    triage_rows = []
    n_ioc_triage = 0
    for rank, i in enumerate(order[: args.top]):
        if not residual[i]:
            break
        hit = ioc_hit(dst[i], nets) or ioc_hit(src[i], nets)
        n_ioc_triage += 1 if hit else 0
        triage_rows.append((rank + 1, fmt_ip(src[i]), fmt_ip(dst[i]), int(dpt[i]),
                            float(ts[i]), float(log_eta[i]), int(byt[i]), hit))

    print('[S4] per-source regime fingerprints ...', flush=True)
    src_times = defaultdict(list)
    for i in range(n):
        src_times[src[i]].append(ts[i])
    print('[S5] M3 magnitudes + b-values ...', flush=True)
    m3 = m3_magnitudes(ts, src, dst)
    # per-source M3 max
    src_m3max = {}
    for i in range(n):
        s = src[i]
        if m3[i] > src_m3max.get(s, -1):
            src_m3max[s] = m3[i]
    source_rows = []
    for s, times in sorted(src_times.items(), key=lambda kv: -len(kv[1])):
        label, cv, r, p, nn = regime_fingerprint(times)
        source_rows.append((fmt_ip(s), nn, label, cv, r, p,
                            src_m3max.get(s, np.nan)))
        if len(source_rows) >= args.max_sources:
            break

    # windowed b-value on M3 (30-min windows) — O(n log n) via searchsorted
    t0 = ts[0]
    win = 1800.0
    ts_np = np.asarray(ts)
    bwin = []
    nb = int(dur // win) + 1 if dur > win else 1
    for w in range(nb):
        lo_i = int(np.searchsorted(ts_np, t0 + w * win))
        hi_i = int(np.searchsorted(ts_np, t0 + (w + 1) * win))
        if hi_i - lo_i < 100:
            continue
        b, a, r2, npts = binned_gr(m3[lo_i:hi_i])
        if b == b:
            bwin.append({'window_min': round(w * win / 60.0, 1), 'b': round(b, 3),
                         'r2': round(r2, 3), 'n_flows': int(hi_i - lo_i)})
    b_all, a_all, r2_all, _ = binned_gr(m3)

    out = args.out
    # triage csv
    with open(out + '_triage.csv', 'w') as f:
        f.write('rank,src,dst,dport,time,log10_eta,bytes,ioc_hit\n')
        for r in triage_rows:
            f.write('%d,%s,%s,%d,%.3f,%.3f,%d,%s\n' % (r[0], r[1], r[2], r[3], r[4], r[5], r[6], int(r[7])))
    with open(out + '_sources.csv', 'w') as f:
        f.write('src,n_flows,regime,cv,lag1_autocorr,omori_slope,M3_max\n')
        for r in source_rows:
            f.write('%s,%d,%s,%.3f,%.3f,%.3f,%.3f\n' % (
                r[0], r[1], r[2],
                r[3] if r[3] == r[3] else -1,
                r[4] if r[4] == r[4] else -1,
                r[5] if r[5] == r[5] else -1, r[6]))
    report = {
        'input': args.input,
        'packets': n_pkt, 'flows': n, 'duration_min': round(dur / 60.0, 2),
        'eta_valley_log10': round(valley, 3), 'valley_auto': auto,
        'retained_flows': int(residual.sum()),
        'retained_pct': round(100.0 * residual.sum() / n, 2),
        'declustered_flows': int(background.sum()),
        'gr_overall_M3': {'b': round(b_all, 3) if b_all == b_all else None,
                          'r2': round(r2_all, 3) if r2_all == r2_all else None},
        'gr_windows': bwin,
        'regime_counts': {lbl: sum(1 for r in source_rows if r[2] == lbl)
                          for lbl in ('omori_decay', 'periodic_beacon', 'bursty_cluster',
                                      'poisson', 'insufficient')},
        'top_triage': [{'rank': r[0], 'src': r[1], 'dst': r[2], 'dport': r[3],
                        'log10_eta': round(r[5], 2), 'ioc_hit': bool(r[7])} for r in triage_rows[:10]],
        'ioc_networks': len(nets),
        'ioc_hits_in_triage_top': n_ioc_triage,
    }
    with open(out + '_report.json', 'w') as f:
        json.dump(report, f, indent=2)

    # console summary
    print('\n================ SEISMIC TRIAGE SUMMARY ================')
    print('catalog: %d flows / %.1f min' % (n, dur / 60.0))
    print('eta valley: log10 eta = %.2f (%s)' % (valley, 'auto-detected' if auto else 'default/given'))
    print('declustering: %d flows retained (%.1f%%) as mainshock candidates' % (
        residual.sum(), 100.0 * residual.sum() / n))
    if b_all == b_all:
        print('GR b-value (M3, whole catalog): b=%.2f R2=%.3f  [tectonic ref b~1]' % (b_all, r2_all))
    print('regimes: ' + json.dumps(report['regime_counts']))
    print('\ntop-10 triage queue (largest eta = most anomalous independence):')
    for r in triage_rows[:10]:
        tag = '  <== IOC' if r[7] else ''
        print('  #%2d  %-15s -> %-15s:%-5d  log10 eta=%6.2f%s' % (r[0], r[1], r[2], r[3], r[5], tag))
    if nets:
        print('IOC hits in top-%d triage queue: %d' % (len(triage_rows), n_ioc_triage))
    if bwin:
        print('\nwindowed b-values (30 min):')
        for w in bwin:
            print('  t+%5.1f min: b=%.3f (R2=%.2f, n=%d)' % (w['window_min'], w['b'], w['r2'], w['n_flows']))
    print('\noutputs: %s_triage.csv | %s_sources.csv | %s_report.json' % (out, out, out))

def main():
    ap = argparse.ArgumentParser(description='Seismic Intrusion Triage Prototype')
    ap.add_argument('input')
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--zeek', action='store_true', help='Zeek conn.log TSV')
    ap.add_argument('--zeek-json', action='store_true', help='Zeek JSON-lines')
    ap.add_argument('--valley', type=float, default=None,
                    help='override eta valley (default: auto-detect, fallback 0.08)')
    ap.add_argument('--top', type=int, default=100, help='triage queue length')
    ap.add_argument('--iocs', default=None, help='file with IOC IPs/CIDRs, one per line')
    ap.add_argument('--max-sources', type=int, default=5000)
    ap.add_argument('--max-flows', type=int, default=None)
    args = ap.parse_args()
    if args.out is None:
        base = os.path.basename(args.input)
        args.out = os.path.splitext(base)[0]
    run(args)

if __name__ == '__main__':
    main()
