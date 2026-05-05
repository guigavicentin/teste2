#!/usr/bin/env python3

import requests
import argparse
import time
import uuid
import json

requests.packages.urllib3.disable_warnings()

# ---------------- HEADERS SSRF ----------------
SSRF_TEST_HEADERS = {
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/internal/config",
    "X-Forwarded-Host": "internal-service.local",
    "X-Host": "internal.local",
    "Host": "internal.local",
    "X-Forwarded-Server": "internal.local",
    "X-HTTP-Host-Override": "internal.local",
    "Forwarded": "for=127.0.0.1;host=internal.local;proto=http"
}

# ---------------- CACHE POISON ----------------
CACHE_POISON_HEADERS = {
    "X-Forwarded-Host": "evil.com",
    "X-Host": "evil.com",
    "Host": "evil.com"
}

SUSPICIOUS_RESPONSE_HEADERS = ["Location", "Link", "X-Cache", "Via"]

findings = []

# ---------------- UTILS ----------------

def normalize(target):
    if target.startswith("http"):
        return target
    return "http://" + target


def get_response_signature(r):
    return (
        r.status_code,
        r.headers.get("Content-Type", ""),
        r.headers.get("Location", ""),
        round(len(r.text), -2)
    )


def analyze_response_headers(r, payload, header_name, url):
    for h in SUSPICIOUS_RESPONSE_HEADERS:
        val = r.headers.get(h, "")
        if "evil.com" in val or "internal" in val:
            print(f"[!] Reflexão no header {h}: {val}")
            findings.append({
                "url": url,
                "header": header_name,
                "payload": payload,
                "type": "HEADER_REFLECTION",
                "evidence": f"{h}: {val}",
                "status": r.status_code
            })


def analyze_redirects(r, header_name, payload, url):
    if r.history:
        for resp in r.history:
            loc = resp.headers.get("Location", "")
            print(f"[REDIRECT] {resp.status_code} → {loc}")
            findings.append({
                "url": url,
                "header": header_name,
                "payload": payload,
                "type": "REDIRECT",
                "evidence": loc,
                "status": resp.status_code
            })


# ---------------- SSRF TEST ----------------

def test_ssrf(url):
    print(f"\n[SSRF] Testando: {url}")

    try:
        base = requests.get(url, timeout=10, verify=False)
        base_sig = get_response_signature(base)
    except:
        print("[-] Falha baseline")
        return

    for header, payload in SSRF_TEST_HEADERS.items():
        try:
            time.sleep(0.2)

            r = requests.get(url, headers={header: payload}, timeout=10, verify=False)
            sig = get_response_signature(r)

            if sig != base_sig:
                print(f"[!] Diferença estrutural via {header}")

                findings.append({
                    "url": url,
                    "header": header,
                    "payload": payload,
                    "type": "SSRF_DIFF",
                    "status": r.status_code,
                    "evidence": "diferença estrutural"
                })

            if "internal" in r.text.lower():
                print(f"[!!] Possível SSRF/reflection via {header}")

                findings.append({
                    "url": url,
                    "header": header,
                    "payload": payload,
                    "type": "SSRF_REFLECTION",
                    "status": r.status_code,
                    "evidence": "internal keyword no body"
                })

            analyze_response_headers(r, payload, header, url)
            analyze_redirects(r, header, payload, url)

        except:
            pass


# ---------------- CACHE POISON ----------------

def test_cache_poison(url):
    print(f"\n[CACHE] Testando: {url}")

    for header, payload in CACHE_POISON_HEADERS.items():
        try:
            buster = str(uuid.uuid4())[:8]
            test_url = f"{url}?cb={buster}"

            time.sleep(0.2)

            poison = requests.get(test_url, headers={header: payload}, timeout=10, verify=False)

            time.sleep(1)

            normal = requests.get(test_url, timeout=10, verify=False)

            analyze_response_headers(poison, payload, header, url)

            if "evil.com" in poison.text.lower():
                print(f"[!] Reflexão detectada via {header}")

                findings.append({
                    "url": url,
                    "header": header,
                    "payload": payload,
                    "type": "CACHE_REFLECTION",
                    "status": poison.status_code,
                    "evidence": "evil.com refletido"
                })

            if poison.text == normal.text and "evil.com" in normal.text.lower():
                print(f"[!!!] Possível CACHE POISON via {header}")

                findings.append({
                    "url": url,
                    "header": header,
                    "payload": payload,
                    "type": "CACHE_POISON",
                    "status": normal.status_code,
                    "evidence": "conteúdo persistente contaminado"
                })

        except:
            pass


# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="SSRF & Cache Poison Tester v2")
    parser.add_argument("-t", "--target", help="Alvo único")
    parser.add_argument("-a", "--arquivo", help="Lista de alvos")

    args = parser.parse_args()

    targets = []

    if args.target:
        targets.append(args.target.strip())

    if args.arquivo:
        with open(args.arquivo) as f:
            targets.extend([l.strip() for l in f if l.strip()])

    if not targets:
        print("Use -t ou -a")
        return

    for t in targets:
        url = normalize(t)

        test_ssrf(url)
        test_cache_poison(url)

    # salvar resultado
    with open("findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    print("\n[+] Resultados salvos em findings.json")


if __name__ == "__main__":
    main()
