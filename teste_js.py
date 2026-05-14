#!/usr/bin/env python3
"""
js_live_crawler.py — Captura os arquivos .js carregados ao VIVO por um site,
exatamente como um browser real faria. Sem caches históricos, sem wayback.

Requerimentos:
    pip install playwright
    playwright install chromium
"""

import asyncio
import argparse
import json
import sys
from urllib.parse import urlparse
from datetime import datetime

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[ERRO] Playwright não instalado. Execute:")
    print("       pip install playwright && playwright install chromium")
    sys.exit(1)


# ─────────────────────────────────────────────
#  Core
# ─────────────────────────────────────────────

async def crawl(url: str, timeout: int, wait: int, headless: bool, output_json: str | None):
    """Abre a URL num browser real e intercepta todos os .js carregados."""

    js_files: list[dict] = []
    seen: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # ── Intercepta cada requisição de rede ──────────────────────────────
        def on_request(request):
            req_url = request.url
            parsed  = urlparse(req_url)
            path    = parsed.path.lower()

            if ".js" in path and req_url not in seen:
                # filtra query strings irrelevantes para o path mas mantém a URL completa
                seen.add(req_url)
                js_files.append({
                    "url":        req_url,
                    "domain":     parsed.netloc,
                    "path":       parsed.path,
                    "resource":   request.resource_type,
                    "initiator":  request.headers.get("referer", "—"),
                })

        page.on("request", on_request)

        # ── Navega ──────────────────────────────────────────────────────────
        print(f"\n🌐  Acessando: {url}")
        print(f"⏳  Aguardando página carregar (timeout {timeout}s, wait extra {wait}s)…\n")

        try:
            await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
        except Exception as e:
            print(f"[AVISO] networkidle timeout: {e}")
            print("        Continuando com o que foi capturado…")

        # Espera adicional para JS assíncrono / lazy load
        if wait > 0:
            await asyncio.sleep(wait)

        await browser.close()

    # ── Resultado ────────────────────────────────────────────────────────────
    target_domain = urlparse(url).netloc
    own    = [j for j in js_files if target_domain in j["domain"]]
    thirds = [j for j in js_files if target_domain not in j["domain"]]

    _print_results(url, js_files, own, thirds)

    if output_json:
        data = {
            "crawled_at":   datetime.utcnow().isoformat() + "Z",
            "target":       url,
            "total":        len(js_files),
            "own_domain":   own,
            "third_party":  thirds,
        }
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n💾  Resultado salvo em: {output_json}")

    return js_files


# ─────────────────────────────────────────────
#  Formatação
# ─────────────────────────────────────────────

def _print_results(url, all_js, own, thirds):
    sep = "─" * 70

    print(sep)
    print(f"  🎯  Target  : {url}")
    print(f"  📦  Total JS: {len(all_js)}")
    print(sep)

    if own:
        print(f"\n  ✅  JS DO PRÓPRIO DOMÍNIO ({len(own)})\n")
        for i, j in enumerate(own, 1):
            print(f"  [{i:02d}] {j['url']}")

    if thirds:
        print(f"\n  🌍  JS DE TERCEIROS ({len(thirds)})\n")
        for i, j in enumerate(thirds, 1):
            domain_label = j["domain"].ljust(35)
            print(f"  [{i:02d}] {domain_label}  {j['path']}")

    print(f"\n{sep}\n")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="js_live_crawler",
        description="Captura .js carregados AO VIVO por um site (como um browser real).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python js_live_crawler.py https://example.com
  python js_live_crawler.py https://example.com -w 3 -o result.json
  python js_live_crawler.py https://example.com --no-headless   # abre o browser visível
        """,
    )
    p.add_argument("url",               help="URL alvo (ex: https://example.com)")
    p.add_argument("-t", "--timeout",   type=int, default=30,   help="Timeout de navegação em segundos (padrão: 30)")
    p.add_argument("-w", "--wait",      type=int, default=2,    help="Segundos extras após networkidle (padrão: 2)")
    p.add_argument("-o", "--output",    default=None,           help="Salvar resultado em JSON (ex: -o result.json)")
    p.add_argument("--no-headless",     action="store_true",    help="Abre o browser visível (útil para debug)")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Garante protocolo
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    asyncio.run(
        crawl(
            url        = url,
            timeout    = args.timeout,
            wait       = args.wait,
            headless   = not args.no_headless,
            output_json= args.output,
        )
    )


if __name__ == "__main__":
    main()
