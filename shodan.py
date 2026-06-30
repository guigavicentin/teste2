"""
Script simples para buscar no Shodan via API oficial.

Requisitos:
    pip install shodan

Uso:
    python shodan_search.py --hostname "exemplo.com.br"
    python shodan_search.py --hostname "exemplo.com.br" --port 443 --product nginx
    python shodan_search.py --query 'org:"Minha Empresa"' --csv saida.csv
"""

import argparse
import csv
import shodan
import sys
import os

# Pode colocar a key aqui, ou exportar a env var SHODAN_API_KEY (recomendado)
API_KEY = os.environ.get("SHODAN_API_KEY", "SUA_API_KEY_AQUI")


def montar_query(args):
    """Monta a query do Shodan combinando filtros, ou usa --query diretamente."""
    if args.query:
        return args.query

    partes = []
    if args.hostname:
        partes.append(f'hostname:"{args.hostname}"')
    if args.org:
        partes.append(f'org:"{args.org}"')
    if args.port:
        partes.append(f"port:{args.port}")
    if args.product:
        partes.append(f'product:"{args.product}"')
    if args.country:
        partes.append(f"country:{args.country}")

    if not partes:
        print("Informe pelo menos um filtro (--hostname, --org, --port, --product, --country) ou use --query.")
        sys.exit(1)

    return " ".join(partes)


def buscar(query: str, limite: int = 100, csv_path: str = None):
    api = shodan.Shodan(API_KEY)

    try:
        resultados = api.search(query, limit=limite)
    except shodan.APIError as e:
        print(f"Erro na API do Shodan: {e}")
        sys.exit(1)

    print(f"Query: {query}")
    print(f"Resultados encontrados: {resultados['total']}")
    print("-" * 50)

    linhas = []
    for item in resultados["matches"]:
        ip = item.get("ip_str")
        porta = item.get("port")
        org = item.get("org", "N/A")
        hostnames = item.get("hostnames", [])
        produto = item.get("product", "N/A")
        versao = item.get("version", "N/A")

        print(f"IP: {ip}")
        print(f"Porta: {porta}")
        print(f"Org: {org}")
        print(f"Hostnames: {', '.join(hostnames) if hostnames else 'N/A'}")
        print(f"Produto/Serviço: {produto} {versao}")
        print("-" * 50)

        linhas.append({
            "ip": ip,
            "porta": porta,
            "org": org,
            "hostnames": ";".join(hostnames),
            "produto": produto,
            "versao": versao,
        })

    if csv_path and linhas:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=linhas[0].keys())
            writer.writeheader()
            writer.writerows(linhas)
        print(f"\nResultados exportados para: {csv_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Busca simples no Shodan")
    parser.add_argument("--hostname", help='Filtro hostname, ex: "exemplo.com.br"')
    parser.add_argument("--org", help='Filtro organização, ex: "Minha Empresa"')
    parser.add_argument("--port", type=int, help="Filtro porta, ex: 443")
    parser.add_argument("--product", help='Filtro produto/serviço, ex: "nginx"')
    parser.add_argument("--country", help="Filtro país (código ISO), ex: BR")
    parser.add_argument("--query", help='Query completa do Shodan, sobrepõe os filtros acima.')
    parser.add_argument("--limite", type=int, default=100, help="Número máximo de resultados (padrão: 100)")
    parser.add_argument("--csv", help="Caminho do arquivo CSV de saída (opcional)")

    args = parser.parse_args()
    query_final = montar_query(args)
    buscar(query_final, limite=args.limite, csv_path=args.csv)
