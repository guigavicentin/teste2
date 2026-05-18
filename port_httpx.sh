#!/usr/bin/env bash
# ──────────────────────────────────────────────
# portscan.sh - Nmap full port + HTTPX em alvo único
# Uso: ./portscan.sh <alvo>
# Ex:  ./portscan.sh ip.sysmo.com.br
# ──────────────────────────────────────────────

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "[ERR] Uso: $0 <alvo>"
  echo "      Ex:  $0 ip.sysmo.com.br"
  exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="scan_${TARGET//./_}_${TS}"
mkdir -p "$OUTDIR"

log()  { echo -e "\033[1;34m[INFO]\033[0m $(date +%H:%M:%S) $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $(date +%H:%M:%S) $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $(date +%H:%M:%S) $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $(date +%H:%M:%S) $*"; }

echo -e "\033[1;32m"
echo "  ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗"
echo "  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║"
echo "  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║"
echo "  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║"
echo "  ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║"
echo "  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
echo -e "\033[0m"
log "Alvo  : $TARGET"
log "Output: $OUTDIR/"

# ──────────────────────────────────────────────
# 1. NMAP full port
# ──────────────────────────────────────────────
log "=== NMAP -p- ==="
NMAP_GNMAP="$OUTDIR/nmap.gnmap"
NMAP_OUT="$OUTDIR/nmap.txt"

nmap -p- -T4 -Pn -sS --open \
  -oG "$NMAP_GNMAP" \
  -oN "$NMAP_OUT" \
  "$TARGET"

ok "Nmap concluído → $NMAP_OUT"

# ──────────────────────────────────────────────
# 2. Extrair portas abertas do gnmap
# ──────────────────────────────────────────────
PORTS=$(grep "Ports:" "$NMAP_GNMAP" \
  | grep -oP '\d+/open/tcp' \
  | cut -d'/' -f1 \
  | sort -n \
  | tr '\n' ',' \
  | sed 's/,$//')

if [[ -z "$PORTS" ]]; then
  err "Nenhuma porta aberta encontrada. Encerrando."
  exit 1
fi

ok "Portas abertas: $PORTS"
echo "$PORTS" > "$OUTDIR/open_ports.txt"

# ──────────────────────────────────────────────
# 3. Montar lista dominio:porta e ip:porta
# ──────────────────────────────────────────────

# Resolve IP do alvo
IP=$(dig +short "$TARGET" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
if [[ -z "$IP" ]]; then
  warn "Não foi possível resolver IP de $TARGET — usando o próprio alvo como IP"
  IP="$TARGET"
fi

ok "IP resolvido: $IP"

DOMAIN_PORTS_FILE="$OUTDIR/domain_ports.txt"
IP_PORTS_FILE="$OUTDIR/ip_ports.txt"
HTTPX_INPUT="$OUTDIR/httpx_input.txt"

> "$DOMAIN_PORTS_FILE"
> "$IP_PORTS_FILE"
> "$HTTPX_INPUT"

IFS=',' read -ra PORT_LIST <<< "$PORTS"
for PORT in "${PORT_LIST[@]}"; do
  echo "${TARGET}:${PORT}" >> "$DOMAIN_PORTS_FILE"
  echo "${IP}:${PORT}"     >> "$IP_PORTS_FILE"
  # httpx_input usa domínio (resolve melhor virtual hosts)
  echo "${TARGET}:${PORT}" >> "$HTTPX_INPUT"
done

ok "domain_ports.txt  → $(wc -l < "$DOMAIN_PORTS_FILE") entradas"
ok "ip_ports.txt      → $(wc -l < "$IP_PORTS_FILE") entradas"

# ──────────────────────────────────────────────
# 4. HTTPX — detectar HTTP/HTTPS ativos
# ──────────────────────────────────────────────
log "=== HTTPX ==="
ALIVE_FILE="$OUTDIR/alive.txt"
ALIVE_JSON="$OUTDIR/alive_json.txt"

# JSON para parse (IP + porta + scheme)
httpx -l "$HTTPX_INPUT" \
  -threads 50 \
  -json \
  -o "$ALIVE_JSON" \
  -silent

# Formato legível
httpx -l "$HTTPX_INPUT" \
  -threads 50 \
  -o "$ALIVE_FILE" \
  -silent

ok "HTTPX concluído → $ALIVE_FILE"

# ──────────────────────────────────────────────
# 5. Gerar arquivos finais consolidados
# ──────────────────────────────────────────────
log "=== CONSOLIDANDO ==="

FINAL_DOMAIN="$OUTDIR/final_dominio_porta.txt"
FINAL_IP_PROTO="$OUTDIR/final_ip_protocolo_porta.txt"
FINAL_IP_SIMPLE="$OUTDIR/final_ip_porta.txt"

> "$FINAL_DOMAIN"
> "$FINAL_IP_PROTO"
> "$FINAL_IP_SIMPLE"

while IFS= read -r LINE; do
  [[ -z "$LINE" ]] && continue

  # Extrai campos do JSON
  URL=$(echo "$LINE"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url',''))"    2>/dev/null || true)
  HOST=$(echo "$LINE"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('host', d.get('input','')))" 2>/dev/null || true)
  PORT=$(echo "$LINE"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('port',''))"   2>/dev/null || true)
  SCHEME=$(echo "$LINE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('scheme','http'))" 2>/dev/null || true)
  RIPA=$(echo "$LINE"   | python3 -c "import sys,json; d=json.load(sys.stdin); a=d.get('a',[]); print(a[0] if a else d.get('ip',''))" 2>/dev/null || true)

  [[ -z "$URL" ]] && continue

  # dominio:porta
  [[ -n "$HOST" && -n "$PORT" ]] && echo "${HOST}:${PORT}" >> "$FINAL_DOMAIN"

  # ip com protocolo
  RIPA="${RIPA:-$IP}"
  [[ -n "$RIPA" && -n "$PORT" ]] && echo "${SCHEME}://${RIPA}:${PORT}" >> "$FINAL_IP_PROTO"

  # ip simples
  [[ -n "$RIPA" && -n "$PORT" ]] && echo "${RIPA}:${PORT}" >> "$FINAL_IP_SIMPLE"

done < "$ALIVE_JSON"

# Deduplica
sort -u -o "$FINAL_DOMAIN"    "$FINAL_DOMAIN"
sort -u -o "$FINAL_IP_PROTO"  "$FINAL_IP_PROTO"
sort -u -o "$FINAL_IP_SIMPLE" "$FINAL_IP_SIMPLE"

# ──────────────────────────────────────────────
# RESUMO
# ──────────────────────────────────────────────
echo
echo -e "\033[1;32m══════════════════════════════════════\033[0m"
ok "Portas abertas (nmap)     : $OUTDIR/open_ports.txt      → $(cat "$OUTDIR/open_ports.txt")"
ok "Domínio:porta (todas)     : $DOMAIN_PORTS_FILE          → $(wc -l < "$DOMAIN_PORTS_FILE") linhas"
ok "IP:porta (todas)          : $IP_PORTS_FILE              → $(wc -l < "$IP_PORTS_FILE") linhas"
ok "URLs ativas (httpx)       : $ALIVE_FILE                 → $(wc -l < "$ALIVE_FILE") ativas"
ok "Domínio:porta (ativos)    : $FINAL_DOMAIN               → $(wc -l < "$FINAL_DOMAIN") linhas"
ok "IP+protocolo (ativos)     : $FINAL_IP_PROTO             → $(wc -l < "$FINAL_IP_PROTO") linhas"
ok "IP:porta simples (ativos) : $FINAL_IP_SIMPLE            → $(wc -l < "$FINAL_IP_SIMPLE") linhas"
echo -e "\033[1;32m══════════════════════════════════════\033[0m"
ok "Tudo salvo em: $OUTDIR/"
