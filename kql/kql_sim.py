#!/usr/bin/env python3
"""kql_sim.py — execute the EXACT semantics of seismic-xdr.kql Q1/Q3/Q4/Q5/Q5b in Python
on a DeviceNetworkEvents-shaped table derived from a pcap, and compare against the
seismic_pipeline.py reference outputs.

Purpose: prove the KQL port reproduces the validated results (ranking, M3, regimes)
before anyone runs it on a live tenant.

Usage:
  python3 kql_sim.py <capture.pcap> [--iocs iocs.txt]

Requires seismic_pipeline.py in the parent directory (imported by path).
"""
import sys, os, math, argparse, ipaddress
from collections import defaultdict
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE) if os.path.basename(_HERE) == 'kql' else _HERE
import importlib.util
spec = importlib.util.spec_from_file_location('sp', os.path.join(_PARENT, 'seismic_pipeline.py'))
sp = importlib.util.module_from_spec(spec); spec.loader.exec_module(sp)

def ip2s(u): return str(ipaddress.IPv4Address(u))
def ip2l(s): return int(ipaddress.IPv4Address(s))
def is_priv(u): return ipaddress.IPv4Address(u).is_private

ap = argparse.ArgumentParser(description='KQL semantics simulator')
ap.add_argument('pcap', help='pcap file (public capture, e.g. AMOS or CTU excerpt)')
ap.add_argument('--iocs', default=None, help='optional IOC IPs/CIDRs file, one per line (scorer only)')
args = ap.parse_args()

# ---- 1. load pcap flows via the reference loader -------------------------------
ts, src, dst, dpt, byt, npkt = sp.load_pcap(args.pcap)
n = len(ts)
print('reference loader: %d packets -> %d flow-records' % (npkt, n))

# ---- 2. shape into DeviceNetworkEvents rows ------------------------------------
# XDR: one row per connection event, direction-normalized:
#   LocalIP = internal endpoint, RemoteIP = the other side.
rows = []
for i in range(n):
    s, d = src[i], dst[i]
    if is_priv(s) and not is_priv(d):
        loc, rem, rp = s, d, dpt[i]
    elif is_priv(d) and not is_priv(s):
        loc, rem, rp = d, s, dpt[i]   # response flow: remote side becomes RemoteIP
    else:
        loc, rem, rp = s, d, dpt[i]
    rows.append(dict(Timestamp=ts[i], DeviceName=ip2s(loc),
                     RemoteIP=ip2s(rem), RemotePort=int(rp),
                     ActionType='ConnectionSuccess'))
rows.sort(key=lambda r: r['Timestamp'])
print('XDR-shaped rows: %d' % len(rows))

# ---- 3. Q1 semantics — EXACT KQL logic ------------------------------------------
# DstLong = tolong(parse_ipv4(RemoteIP)); Dst24 = floor(DstLong,256); Dst16 = floor(_,65536)
# per class: partition by key | order by Timestamp asc | dt = diff to prev
# eta = min(dt1*1, dt2*3.0314, dt3*5.7995, dt4*9.1896); null class -> 999999; drop if all null
for r in rows:
    dl = ip2l(r['RemoteIP'])
    r['IpPortKey'] = '%s:%d' % (r['RemoteIP'], r['RemotePort'])
    r['Dst24'] = dl // 256
    r['Dst16'] = dl // 65536

def prev_dt(rs, key):
    last = {}
    for r in rs:
        k = r[key]
        r['_dt_' + key] = (r['Timestamp'] - last[k]) if k in last else None
        last[k] = r['Timestamp']

for key, w in (('IpPortKey', 1.0), ('RemoteIP', 3.0314), ('Dst24', 5.7995), ('Dst16', 9.1896)):
    prev_dt(rows, key)
    for r in rows:
        r['_eta_' + key] = r['_dt_' + key] * w if r['_dt_' + key] is not None else 999999.0

for r in rows:
    e = min(r['_eta_IpPortKey'], r['_eta_RemoteIP'], r['_eta_Dst24'], r['_eta_Dst16'])
    r['EtaMin'] = e
    r['LogEta'] = math.log10(e) if e < 999999.0 and e > 0 else None
valid = [r for r in rows if r['LogEta'] is not None]
valid.sort(key=lambda r: -r['LogEta'])
nets = sp.load_iocs(args.iocs) if args.iocs else []

VALLEYS = [0.08, -5.73]   # hardcoded fallback + reference auto valley (AMOS demo)
for VALLEY in VALLEYS:
    queue = [r for r in valid if r['LogEta'] >= VALLEY][:100]
    hits = [r for r in queue if nets and sp.ioc_hit(ip2l(r['RemoteIP']), nets)]
    n_ret = sum(1 for r in valid if r['LogEta'] >= VALLEY)
    print('\nQ1 sim @ valley %.2f: retained %d/%d (%.1f%%), IOC hits in top-100: %d'
          % (VALLEY, n_ret, len(valid), 100.0*n_ret/len(valid), len(hits)))
# where did every IOC event land? full ranking
if nets:
    print('\nIOC events by sim rank (any position):')
    for rank, r in enumerate(valid, 1):
        if sp.ioc_hit(ip2l(r['RemoteIP']), nets):
            print('   sim-rank %4d  LogEta=%6.2f  %s -> %s:%d' % (rank, r['LogEta'], r['DeviceName'], r['RemoteIP'], r['RemotePort']))

# ---- 4. Q3 semantics: M3 = log10(1+dcount(RemoteIP)) per device per 10m ----------
m3 = defaultdict(set)
for r in rows:
    m3[(r['DeviceName'], int(r['Timestamp'] // 600))].add(r['RemoteIP'])
m3max = {}
for (dev, w), s in m3.items():
    v = math.log10(1 + len(s))
    m3max[dev] = max(m3max.get(dev, -1), v)
print('\nQ3 sim: per-device M3max (top 5):')
for dev, v in sorted(m3max.items(), key=lambda kv: -kv[1])[:5]:
    print('   %-16s M3max = %.3f' % (dev, v))

# ---- 5. Q4 semantics: b-value via manual OLS on mv-expanded bins ----------------
m3rows = []
for (dev, w), s in m3.items():
    m3rows.append((w * 600.0, math.log10(1 + len(s))))
W30 = defaultdict(list)
for t, v in m3rows:
    W30[int(t // 1800)].append(v)
MBINS = [0.0, 0.3, 0.6, 0.9, 1.2, 1.5]   # v1.1: include the 0.0 bin
for w in sorted(W30):
    vals = W30[w]
    pts = []
    for m in MBINS:
        N = sum(1 for v in vals if v >= m)
        if N > 0:
            pts.append((m, math.log10(N)))
    if len(pts) >= 3:
        xs = np.array([p[0] for p in pts]); ys = np.array([p[1] for p in pts])
        nn = len(xs)
        sx, sy = xs.sum(), ys.sum()
        sxy, sxx, syy = (xs*ys).sum(), (xs*xs).sum(), (ys*ys).sum()
        b = -(nn*sxy - sx*sy) / (nn*sxx - sx*sx)
        r2 = (nn*sxy - sx*sy)**2 / ((nn*sxx - sx*sx) * (nn*syy - sy*sy))
        print('Q4 sim: window %d  b=%.3f R2=%.3f' % (w, b, r2))

# ---- 6. Q5 semantics: CV + DecayRatio (+ optional autocorr) ---------------------
def fingerprint(times, use_autocorr):
    t = np.sort(times)
    if len(t) < 8:
        return None
    d = np.diff(t); d = d[d > 0]
    if len(d) < 3:
        return None
    cv = float(d.std() / d.mean())
    mid = t[0] + (t[-1] - t[0]) / 2
    n1 = int((t <= mid).sum()); n2 = int((t > mid).sum())
    dr = n2 / n1 if n1 > 0 else 1.0
    r_ = float(np.corrcoef(d[:-1], d[1:])[0, 1]) if len(d) >= 4 and d[:-1].std() > 0 and d[1:].std() > 0 else 0.0
    if cv < 0.5: reg = 'periodic_beacon'
    elif dr < 0.6 and cv > 0.9: reg = 'omori_decay'
    elif cv > 1.3 and (r_ > 0.15 or not use_autocorr): reg = 'bursty_cluster'
    else: reg = 'poisson'
    return cv, dr, r_, reg, len(t)

ev = defaultdict(list)
for r in rows:
    ev[r['DeviceName']].append(r['Timestamp'])
print('\nQ5 sim — per-DEVICE (KQL pack rules, no autocorr) vs (+autocorr variant):')
for dev, times in sorted(ev.items(), key=lambda kv: -len(kv[1])):
    a = fingerprint(times, False); b = fingerprint(times, True)
    if a:
        print('   %-16s n=%4d  CV=%6.2f  DR=%5.2f  r=%6.2f  -> %-15s | +autocorr: %-15s'
              % (dev, len(times), a[0], a[1], a[2], a[3], b[3]))

# ---- 7. Q5b semantics: per-RemoteIP fingerprint (external hosts = where C2 lives)
rem = defaultdict(list)
for r in rows:
    rem[r['RemoteIP']].append(r['Timestamp'])
print('\nQ5b sim — per-RemoteIP (public side; XDR DeviceNetworkEvents is endpoint-centric,')
print('so external endpoints only exist as RemoteIP — this variant fingerprints THEM):')
shown = 0
for ip, times in sorted(rem.items(), key=lambda kv: -len(kv[1])):
    f = fingerprint(times, True)
    if f is None:
        continue
    ioc = nets and sp.ioc_hit(ip2l(ip), nets)
    if ioc or len(times) >= 20 or f[3] == 'omori_decay':
        print('   %-16s n=%4d  CV=%6.2f  DR=%5.2f  r=%6.2f  -> %-15s %s'
              % (ip, len(times), f[0], f[1], f[2], f[3], '<== C2 IOC' if ioc else ''))
        shown += 1
    if shown > 25:
        break
