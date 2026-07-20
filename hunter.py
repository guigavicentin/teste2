#!/usr/bin/env python3
"""
XSS Hunter — gau + waybackurls + katana → httpx (probe) → GF → nuclei DAST full / dalfox XSS
"""

import subprocess
import sys
import shutil
import argparse
import random
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
R     = "\033[0m"
BOLD  = "\033[1m"
RED   = "\033[91m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
BLUE  = "\033[94m"
CYAN  = "\033[96m"
MAG   = "\033[95m"
DIM   = "\033[2m"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR      = Path(__file__).resolve().parent
TEMPLATES_ROOT  = SCRIPT_DIR / "nuclei_fuzz" / "fuzzing-templates"

# ---------------------------------------------------------------------------
# User-Agent pool
# ---------------------------------------------------------------------------
FAKE_UAS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]


def pick_ua(ua_arg: str | None, no_spoof: bool) -> str | None:
    if no_spoof:
        return None
    if ua_arg:
        return ua_arg
    return random.choice(FAKE_UAS)

TEMPLATE_GF_MAP: dict[str, list[str]] = {
    "cmdi":     ["rce"],
    "crlf":     ["interestingparams"],
    "csti":     ["ssti"],
    "lfi":      ["lfi"],
    "redirect": ["redirect"],
    "rfi":      ["lfi"],
    "sqli":     ["sqli"],
    "ssrf":     ["ssrf"],
    "ssti":     ["ssti"],
    "xss":      ["xss"],
    "xxe":      ["interestingparams"],
}

REQUIRED_TOOLS = {
    "gau":         "go install github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "httpx":       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gf":          "go install github.com/tomnomnom/gf@latest",
    "nuclei":      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "dalfox":      "go install github.com/hahwul/dalfox/v2@latest",
}


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
def banner():
    print(f"""\n{CYAN}{BOLD}\
╔══════════════════════════════════════════════════════════════╗
║                     XSS Hunter v1.2                          ║
║  gau+wayback+katana → httpx (probe) → gf → nuclei/dalfox      ║
╚══════════════════════════════════════════════════════════════╝{R}\n""")

def section(title: str):
    print(f"\n{BOLD}{MAG}{'─'*62}{R}")
    print(f"{BOLD}{MAG}  {title}{R}")
    print(f"{BOLD}{MAG}{'─'*62}{R}\n")

def ok(msg):   print(f"{GREEN}[✓]{R} {msg}")
def info(msg): print(f"{CYAN}[*]{R} {msg}")
def warn(msg): print(f"{YELLOW}[!]{R} {msg}")
def err(msg):  print(f"{RED}[✗]{R} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Tool / template check
# ---------------------------------------------------------------------------
def check_tools() -> tuple[bool, bool, set[str], list[str]]:
    section("Verificando ferramentas")
    missing = []
    for tool, hint in REQUIRED_TOOLS.items():
        path = shutil.which(tool)
        tag  = f"{GREEN}✓{R}" if path else f"{RED}✗{R}"
        loc  = f"{BLUE}{path}{R}" if path else f"{YELLOW}não encontrado{R}"
        print(f"  {tag}  {tool:<16} {loc}")
        if not path:
            missing.append((tool, hint))

    if missing:
        print(f"\n{RED}{BOLD}Ferramentas faltando — instale com:{R}")
        for tool, hint in missing:
            print(f"  {YELLOW}$ {hint}{R}")
        sys.exit(1)

    gf_dir = Path.home() / ".gf"
    available_gf: set[str] = set()
    if gf_dir.is_dir():
        available_gf = {f.stem for f in gf_dir.glob("*.json")}

    template_dirs: list[str] = []
    if TEMPLATES_ROOT.is_dir():
        template_dirs = sorted(
            d.name for d in TEMPLATES_ROOT.iterdir()
            if d.is_dir() and (d / "").exists()
        )
    else:
        warn(f"Templates nuclei não encontrados em: {TEMPLATES_ROOT}")

    nuclei_ok  = bool(template_dirs)
    dalfox_ok  = True

    print(f"\n  {BOLD}GF patterns disponíveis:{R} {', '.join(sorted(available_gf))}")
    if template_dirs:
        print(f"  {BOLD}Template dirs encontrados:{R} {', '.join(template_dirs)}")
    else:
        warn("Nenhum template nuclei encontrado — modo nuclei indisponível")

    ok("Ferramentas prontas!\n")
    return nuclei_ok, dalfox_ok, available_gf, template_dirs


# ---------------------------------------------------------------------------
# URL collection (sem timeout)
# ---------------------------------------------------------------------------
def stream_collect(cmd: list[str], label: str) -> list[str]:
    print(f"  {BLUE}$ {' '.join(cmd)}{R}")
    urls: list[str] = []
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc.stdout:
            u = line.strip()
            if u:
                urls.append(u)
                if len(urls) % 500 == 0:
                    print(f"    {CYAN}... {len(urls)} URLs{R}", end="\r", flush=True)
        proc.wait()
    except FileNotFoundError:
        err(f"Comando não encontrado: {cmd[0]}")
    except KeyboardInterrupt:
        warn(f"{label} interrompido pelo usuário — usando o que foi coletado")
        if proc:
            proc.terminate()
    print(f"    {GREEN}✓{R} {label}: {len(urls)} URLs        ")
    return urls


def collect_urls(target: str, scheme: str, output_dir: Path) -> Path:
    section("Fase 1/4 — Coleta de URLs")
    base_url = f"{scheme}://{target}"
    pool: set[str] = set()

    print(f"\n{MAG}[gau]{R}")
    pool.update(stream_collect(["gau", "--subs", target], "gau"))

    print(f"\n{MAG}[waybackurls]{R}")
    pool.update(stream_collect(["waybackurls", target], "waybackurls"))

    print(f"\n{MAG}[katana]{R}")
    pool.update(stream_collect(
        ["katana", "-u", base_url, "-d", "3", "-f", "qurl", "-silent"],
        "katana",
    ))

    out = output_dir / "all_urls.txt"
    out.write_text("\n".join(sorted(pool)) + "\n")
    ok(f"Total dedupado (bruto): {len(pool)} URLs  →  {out}")
    return out


# ---------------------------------------------------------------------------
# httpx probing — remove mortas / 404 / 403 / etc, e deduplica de novo
# ---------------------------------------------------------------------------
DEFAULT_MATCH_CODES = "200,201,202,204,301,302,307,308"


def run_httpx_probe(
    all_urls_file: Path,
    output_dir: Path,
    match_codes: str = DEFAULT_MATCH_CODES,
    threads: int = 50,
    timeout: int = 10,
    follow_redirects: bool = True,
    ua: str | None = None,
) -> tuple[Path, int]:
    """
    Roda httpx sobre a lista bruta de URLs e devolve só as que respondem
    com status code "vivo" (por padrão exclui 403/404/etc, que ficam de fora
    de match_codes). Também deduplica novamente, pois o httpx normaliza
    (segue redirects, resolve host, etc) e pode gerar convergência de URLs
    que antes pareciam distintas.
    """
    section("Fase 2/4 — Probing com httpx (remover 404/403/mortas)")

    out = output_dir / "httpx_alive.txt"

    cmd = [
        "httpx",
        "-l",              str(all_urls_file),
        "-mc",             match_codes,     # match apenas esses status codes
        "-silent",
        "-threads",        str(threads),
        "-timeout",        str(timeout),
        "-o",              str(out),
    ]
    if follow_redirects:
        cmd.append("-fr")
    if ua:
        cmd += ["-H", f"User-Agent: {ua}"]

    print(f"{BLUE}$ {' '.join(cmd)}{R}")
    print(f"  {DIM}Match status codes: {match_codes}{R}")
    print(f"{YELLOW}(sem timeout global — Ctrl+C para interromper){R}\n")

    alive: set[str] = set()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc.stdout:
            u = line.strip()
            if u:
                alive.add(u)
                if len(alive) % 200 == 0:
                    print(f"    {CYAN}... {len(alive)} vivas{R}", end="\r", flush=True)
        proc.wait()
    except FileNotFoundError:
        err("httpx não encontrado no PATH.")
        sys.exit(1)
    except KeyboardInterrupt:
        warn("httpx interrompido pelo usuário — usando o que foi coletado até agora")
        if proc:
            proc.terminate()

    # Dedup final (httpx com -fr pode devolver a mesma URL final para
    # múltiplas origens diferentes)
    deduped = sorted(alive)
    out.write_text("\n".join(deduped) + "\n")

    total_before = sum(1 for l in all_urls_file.open() if l.strip())
    print(f"\n    {GREEN}✓{R} httpx: {len(deduped)}/{total_before} URLs vivas (status em [{match_codes}])        ")
    ok(f"URLs vivas e dedupadas  →  {out}")
    return out, len(deduped)


# ---------------------------------------------------------------------------
# GF filtering
# ---------------------------------------------------------------------------
def run_gf(pattern: str, urls_text: str) -> set[str]:
    r = subprocess.run(["gf", pattern], input=urls_text, capture_output=True, text=True)
    return {u for u in r.stdout.splitlines() if u.strip()}


def filter_gf_all(
    all_urls_file: Path,
    output_dir: Path,
    template_dirs: list[str],
    available_gf: set[str],
) -> tuple[Path, int]:
    section("Fase 3/4 — GF multi-padrão (para nuclei)")
    urls_text = all_urls_file.read_text()
    total_pool: set[str] = set()

    col_cat  = 16
    col_gf   = 20
    col_urls = 8

    header = (f"  {BOLD}{'Categoria':<{col_cat}} {'GF Pattern':<{col_gf}} "
              f"{'URLs':>{col_urls}}  Status{R}")
    print(header)
    print(f"  {'─'*62}")

    used_gf_patterns: set[str] = set()

    for cat in template_dirs:
        patterns = TEMPLATE_GF_MAP.get(cat, [])
        matched: set[str] = set()
        used_pat = []

        for pat in patterns:
            if pat in available_gf:
                hits = run_gf(pat, urls_text)
                matched.update(hits)
                used_pat.append(pat)
                used_gf_patterns.add(pat)

        total_pool.update(matched)

        if used_pat:
            pat_label = ", ".join(used_pat)
            cnt_color = GREEN if matched else DIM
            status    = f"{cnt_color}{len(matched):>{col_urls}}{R}"
        else:
            pat_label = f"{DIM}sem mapeamento GF{R}"
            status    = f"{YELLOW}{'skip':>{col_urls}}{R}"

        print(f"  {CYAN}{cat:<{col_cat}}{R} {pat_label:<{col_gf}} {status}")

    gf_all_file = output_dir / "gf_nuclei.txt"
    gf_all_file.write_text("\n".join(sorted(total_pool)) + "\n")

    print(f"\n  {DIM}GF patterns usados: {', '.join(sorted(used_gf_patterns))}{R}")
    ok(f"Total consolidado: {len(total_pool)} endpoints únicos  →  {gf_all_file}")
    return gf_all_file, len(total_pool)


def filter_gf_xss(all_urls_file: Path, output_dir: Path) -> tuple[Path, int]:
    urls_text = all_urls_file.read_text()
    xss_urls  = sorted(run_gf("xss", urls_text))
    out       = output_dir / "gf_xss.txt"
    out.write_text("\n".join(xss_urls) + "\n")
    return out, len(xss_urls)


# ---------------------------------------------------------------------------
# Engine choice
# ---------------------------------------------------------------------------
def ask_engine(nuclei_ok: bool) -> str:
    section("Fase 4/4 — Escolha do motor de varredura")
    opts = []
    if nuclei_ok:
        opts.append(("1", "Nuclei DAST (full)", "todos os templates: cmdi/crlf/lfi/sqli/ssrf/ssti/xss/xxe/…"))
    opts.append(("2", "Dalfox (XSS only)",
                 "scanner XSS especializado, mining de parâmetros DOM"))
    if nuclei_ok:
        opts.append(("3", "Ambos", "nuclei DAST completo + dalfox XSS em sequência"))
    opts.append(("0", "Sair", "salvar arquivos e encerrar"))

    for key, name, desc in opts:
        color = RED if key == "0" else CYAN
        print(f"  {color}[{key}]{R}  {BOLD}{name:<22}{R} {DIM}{desc}{R}")

    valid = {k for k, _, _ in opts}
    while True:
        choice = input(f"\n{BOLD}Opção [{'/'.join(sorted(valid))}]: {R}").strip()
        if choice in valid:
            return choice
        warn("Opção inválida.")


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------
def run_nuclei(gf_file: Path, output_dir: Path, extra: list[str], ua: str | None = None):
    section("Nuclei DAST — varredura completa")
    out = output_dir / "nuclei_results.txt"

    ua_flags = ["-H", f"User-Agent: {ua}"] if ua else []
    if ua:
        print(f"  {DIM}User-Agent: {ua}{R}\n")

    cmd = [
        "nuclei",
        "-list",     str(gf_file),
        "-t",        str(TEMPLATES_ROOT),
        "-dast",
        "-o",        str(out),
        "-no-color",
        *ua_flags,
        *extra,
    ]
    print(f"{BLUE}$ {' '.join(cmd)}{R}")
    print(f"{YELLOW}(sem timeout — Ctrl+C para interromper){R}\n")

    SEV_HIGH = {"[critical]", "[high]", "[medium]"}
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            ll = line.lower()
            if any(s in ll for s in SEV_HIGH):
                print(f"{RED}{BOLD}{line}{R}")
            elif "[info]" in ll:
                print(f"{CYAN}{line}{R}")
            else:
                print(line)
        proc.wait()
    except KeyboardInterrupt:
        warn("Nuclei interrompido.")
        if proc: proc.terminate()

    if out.exists() and out.stat().st_size > 0:
        count = len(out.read_text().splitlines())
        ok(f"Nuclei: {count} findings  →  {out}")
    else:
        warn("Nuclei: sem findings")


# ---------------------------------------------------------------------------
# Dalfox
# ---------------------------------------------------------------------------
def run_dalfox(gf_file: Path, output_dir: Path, extra: list[str], ua: str | None = None):
    section("Dalfox — XSS scanner")
    out = output_dir / "dalfox_results.txt"

    ua_flags = ["-H", f"User-Agent: {ua}"] if ua else []
    if ua:
        print(f"  {DIM}User-Agent: {ua}{R}\n")

    cmd = [
        "dalfox", "file", str(gf_file),
        "--output",   str(out),
        "--format",   "plain",
        "--no-spinner",
        "--only-poc", "v",
        *ua_flags,
        *extra,
    ]
    print(f"{BLUE}$ {' '.join(cmd)}{R}")
    print(f"{YELLOW}(sem timeout — Ctrl+C para interromper){R}\n")

    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            if "[V]" in line or "VULN" in line.upper() or "POC" in line.upper():
                print(f"{RED}{BOLD}{line}{R}")
            elif "[I]" in line or "[W]" in line:
                print(f"{CYAN}{line}{R}")
            else:
                print(line)
        proc.wait()
    except KeyboardInterrupt:
        warn("Dalfox interrompido.")
        if proc: proc.terminate()

    if out.exists() and out.stat().st_size > 0:
        count = len(out.read_text().splitlines())
        ok(f"Dalfox: {count} findings  →  {out}")
    else:
        warn("Dalfox: sem findings")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
EXAMPLES = """\
exemplos:
  # básico — UA aleatório da pool por padrão (bypass WAF)
  python3 xss_hunter.py example.com

  # customizar quais status codes o httpx deve considerar "vivos"
  python3 xss_hunter.py example.com --httpx-mc 200,301,302

  # pular a etapa de probing httpx (usar todas as URLs cruas)
  python3 xss_hunter.py example.com --skip-httpx

  # mais threads no httpx
  python3 xss_hunter.py example.com --httpx-threads 100

  # passar rate-limit e concorrência para o nuclei
  python3 xss_hunter.py example.com --nuclei-flags -rl 10 -c 5

  # passar cookie de sessão e blind XSS callback para o dalfox
  python3 xss_hunter.py example.com --dalfox-flags -C "session=abc123" -b "https://blind.example.com"

  # ver pool completo de User-Agents disponíveis
  python3 xss_hunter.py --list-uas
"""


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="XSS Hunter — coleta endpoints e varre vulnerabilidades web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    parser.add_argument("target", nargs="?", help="Domínio alvo (ex: example.com)")
    parser.add_argument(
        "--scheme", default="https", choices=["https", "http"],
        help="Scheme para katana (padrão: https)",
    )
    ua_group = parser.add_mutually_exclusive_group()
    ua_group.add_argument("--ua", metavar="STRING", help="User-Agent customizado")
    ua_group.add_argument("--no-ua-spoof", action="store_true", help="Desativar UA spoofing")
    parser.add_argument("--list-uas", action="store_true", help="Exibir pool de UAs e sair")

    # ── httpx probing ────────────────────────────────────────────────────────
    parser.add_argument(
        "--skip-httpx", action="store_true",
        help="Pular etapa de probing httpx (não filtra 404/403/mortas)",
    )
    parser.add_argument(
        "--httpx-mc", metavar="CODES", default=DEFAULT_MATCH_CODES,
        help=f"Status codes considerados 'vivos' (padrão: {DEFAULT_MATCH_CODES})",
    )
    parser.add_argument("--httpx-threads", type=int, default=50, help="Threads do httpx (padrão: 50)")
    parser.add_argument("--httpx-timeout", type=int, default=10, help="Timeout por request do httpx em segundos (padrão: 10)")
    parser.add_argument(
        "--httpx-no-follow-redirects", action="store_true",
        help="Não seguir redirects no httpx (por padrão segue com -fr)",
    )

    parser.add_argument("--nuclei-flags", nargs=argparse.REMAINDER, default=[])
    parser.add_argument("--dalfox-flags", nargs=argparse.REMAINDER, default=[])
    args = parser.parse_args()

    if args.list_uas:
        print(f"\n{BOLD}Pool de User-Agents ({len(FAKE_UAS)} entradas):{R}\n")
        for i, ua in enumerate(FAKE_UAS, 1):
            print(f"  {CYAN}[{i:02d}]{R} {ua}")
        print()
        sys.exit(0)

    nuclei_ok, _, available_gf, template_dirs = check_tools()

    ua = pick_ua(args.ua, args.no_ua_spoof)
    if ua:
        src = "customizado" if args.ua else f"aleatório ({len(FAKE_UAS)} na pool)"
        info(f"User-Agent {src}:")
        print(f"  {DIM}{ua}{R}\n")
    else:
        warn("UA spoofing desativado — usando padrão das ferramentas.\n")

    target = args.target
    if not target:
        target = input(f"\n{BOLD}[?] Domínio alvo (sem https://): {R}").strip()
        target = (target
                  .removeprefix("https://")
                  .removeprefix("http://")
                  .rstrip("/"))
    if not target:
        err("Alvo não especificado."); sys.exit(1)

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
    output_dir = SCRIPT_DIR / "out" / f"xss_{safe}_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)
    info(f"Output: {output_dir}\n")

    # ── fase 1: coleta ──────────────────────────────────────────────────────
    all_urls_file = collect_urls(target, args.scheme, output_dir)
    total = sum(1 for l in all_urls_file.open() if l.strip())
    if total == 0:
        warn("Nenhuma URL coletada. Verifique o alvo e sua conexão."); sys.exit(0)

    # ── fase 2: probing httpx (remove 404/403/mortas + dedup final) ─────────
    working_file = all_urls_file
    if not args.skip_httpx:
        working_file, alive_count = run_httpx_probe(
            all_urls_file,
            output_dir,
            match_codes=args.httpx_mc,
            threads=args.httpx_threads,
            timeout=args.httpx_timeout,
            follow_redirects=not args.httpx_no_follow_redirects,
            ua=ua,
        )
        if alive_count == 0:
            warn("httpx não encontrou nenhuma URL viva. Encerrando.")
            sys.exit(0)
    else:
        warn("Probing httpx pulado (--skip-httpx) — usando URLs cruas, incluindo possíveis 404/403.\n")

    # ── engine choice ────────────────────────────────────────────────────────
    choice = ask_engine(nuclei_ok)
    if choice == "0":
        print(f"\n{YELLOW}Saindo. Arquivos em: {output_dir}{R}"); sys.exit(0)

    # ── fase 3: GF (conforme engine escolhida), a partir das URLs vivas ─────
    gf_nuclei_file = gf_xss_file = None
    gf_nuclei_count = gf_xss_count = 0

    if choice in ("1", "3") and nuclei_ok:
        gf_nuclei_file, gf_nuclei_count = filter_gf_all(
            working_file, output_dir, template_dirs, available_gf
        )
        if gf_nuclei_count == 0:
            warn("GF não encontrou endpoints para nuclei — pulando nuclei.")
            choice = "2" if choice == "3" else "0"

    if choice in ("2", "3"):
        info("Filtrando endpoints XSS para dalfox...")
        gf_xss_file, gf_xss_count = filter_gf_xss(working_file, output_dir)
        print(f"  {GREEN}✓{R} gf xss: {gf_xss_count} endpoints  →  {gf_xss_file}")
        if gf_xss_count == 0:
            warn("GF xss: sem endpoints candidatos.")

    # ── fase 4: scan ──────────────────────────────────────────────────────────
    if choice in ("1", "3") and gf_nuclei_file and gf_nuclei_count:
        run_nuclei(gf_nuclei_file, output_dir, args.nuclei_flags, ua)

    if choice in ("2", "3") and gf_xss_file and gf_xss_count:
        run_dalfox(gf_xss_file, output_dir, args.dalfox_flags, ua)

    # ── sumário ───────────────────────────────────────────────────────────────
    print(f"\n{GREEN}{BOLD}{'═'*62}{R}")
    print(f"{GREEN}{BOLD}  Varredura concluída!{R}")
    print(f"{GREEN}{BOLD}{'═'*62}{R}")
    print(f"  {BOLD}Alvo:         {R}{target}")
    print(f"  {BOLD}URLs brutas:  {R}{total}")
    if not args.skip_httpx:
        print(f"  {BOLD}URLs vivas:   {R}{sum(1 for l in working_file.open() if l.strip())}")
    if gf_nuclei_count:
        print(f"  {BOLD}GF (nuclei):  {R}{gf_nuclei_count} endpoints ({len(template_dirs)} categorias)")
    if gf_xss_count is not None and choice in ("2", "3"):
        print(f"  {BOLD}GF (dalfox):  {R}{gf_xss_count} endpoints XSS")
    print(f"  {BOLD}Output:       {R}{output_dir}")
    print()


if __name__ == "__main__":
    main()
