#!/usr/bin/env bash
# Runs azure-edr-inventory.sh against the mock az CLI in tests/mock and checks the reports.
# Needs only bash and jq - no Azure access.
# SPDX-License-Identifier: MIT
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../azure-edr-inventory.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PATH="$HERE/mock:$PATH"

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }
# row <file> <machine or subscription name> -> that row (first column of machines.tsv is risk)
row() { awk -F'\t' -v n="$2" '$3 == n || $1 == n' "$1"; }
# col <file> <row-name> <column header> -> the value
col() {
  awk -F'\t' -v n="$2" -v h="$3" 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == h) c = i; next}
                                  ($3 == n || $1 == n) {print $c}' "$1"
}
is() {  # is <description> <actual> <expected>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', expected '$3')"; fi
}

M="$WORK/out/machines.tsv"; S="$WORK/out/subscriptions.tsv"

echo "whole tenant"
if bash "$SCRIPT" -o "$WORK/out" 2>"$WORK/log"; then ok "exits 0"; else bad "exits 0"; cat "$WORK/log"; fi
is "11 machines (VMs over two Resource Graph pages, scale sets, Arc)" "$(($(wc -l < "$M") - 1))" 11
is "MDE present -> LOW"                       "$(col "$M" vm-win-ok risk)" LOW
is "no agent + SSH open via NIC NSG -> CRITICAL" "$(col "$M" vm-lnx-exposed risk)" CRITICAL
is "  ... open port is 22 only"               "$(col "$M" vm-lnx-exposed mgmtPortsOpenToInternet)" 22
is "  ... plan on but no sensor"              "$(col "$M" vm-lnx-exposed endpointProtection)" "NONE - Defender plan on, no sensor"
is "Antimalware only = AV ONLY"               "$(col "$M" vm-win-av endpointProtection)" "AV ONLY"
is "Basic public IP without NSG: all ports open" "$(col "$M" vm-win-av mgmtPortsOpenToInternet)" "22, 3389, 5985, 5986"
is "  ... -> CRITICAL"                        "$(col "$M" vm-win-av risk)" CRITICAL
is "other EDR vendor recognised"              "$(col "$M" vm-lnx-cs endpointProtection)" "OTHER EDR: CrowdStrike.Falcon.FalconSensorLinux"
is "subnet NSG: deny 22 wins by priority, 3389 in allowed range" "$(col "$M" vm-lnx-cs mgmtPortsOpenToInternet)" 3389
is "  ... protected but exposed -> HIGH"      "$(col "$M" vm-lnx-cs risk)" HIGH
is "Standard public IP without NSG: closed"   "$(col "$M" vm-lnx-std mgmtPortsOpenToInternet)" ""
is "  ... unprotected and running -> HIGH"    "$(col "$M" vm-lnx-std risk)" HIGH
is "plan read via REST when missing from Resource Graph" "$(col "$M" vm-lnx-std defenderPlan)" Free
is "failed MDE extension counts as unprotected" "$(col "$M" vm-lnx-mdefail risk)" HIGH
is "MDE integration off is reported"          "$(col "$M" vm-win-off endpointProtection)" "NONE - Defender plan on, MDE integration off"
is "deallocated VM -> MEDIUM"                 "$(col "$M" vm-win-off risk)" MEDIUM
is "AKS node pool flagged"                    "$(col "$M" aks-nodepool1-vmss aksNodePool)" yes
is "  ... unprotected AKS nodes -> MEDIUM"    "$(col "$M" aks-nodepool1-vmss risk)" MEDIUM
is "MDE in scale set model recognised"        "$(col "$M" web-vmss endpointProtection)" MDE
is "Arc machine with MDE"                     "$(col "$M" arc-win endpointProtection)" MDE
is "disconnected Arc machine -> MEDIUM"       "$(col "$M" arc-lnx risk)" MEDIUM
is "management group path, root first"        "$(col "$M" vm-win-ok managementGroups)" "Tenant Root Group / Prod"
is "subscriptions report: 4 rows"             "$(($(wc -l < "$S") - 1))" 4
is "prod-app: P1, integration on"             "$(row "$S" prod-app | cut -f4-6)" "$(printf 'Standard\tP1\ttrue')"
is "prod-app: 4 machines, 2 unprotected, 1 critical" "$(row "$S" prod-app | cut -f7,9,12)" "$(printf '4\t2\t1')"
is "platform: integration off"                "$(col "$S" platform mdeIntegration)" false
perm=$(stat -c %a "$M" 2>/dev/null || stat -f %Lp "$M")
is "reports readable by owner only"           "$perm" 600

echo "-s (one subscription)"
bash "$SCRIPT" -s 11111111-0000-0000-0000-000000000002 -o "$WORK/one" 2>/dev/null
is "only dev machines"                        "$(cut -f4 "$WORK/one/machines.tsv" | tail -n +2 | sort -u)" dev
is "one subscription row"                     "$(($(wc -l < "$WORK/one/subscriptions.tsv") - 1))" 1

echo "-p (custom ports)"
bash "$SCRIPT" -p "22" -o "$WORK/ports" 2>/dev/null
is "only port 22 checked"                     "$(col "$WORK/ports/machines.tsv" vm-win-av mgmtPortsOpenToInternet)" 22
is "3389 no longer counted -> LOW"            "$(col "$WORK/ports/machines.tsv" vm-lnx-cs risk)" LOW

echo "-r (scheduled start/stop: stopped VMs rated as running)"
bash "$SCRIPT" -r -o "$WORK/sched" 2>/dev/null
is "deallocated unprotected VM -> HIGH"       "$(col "$WORK/sched/machines.tsv" vm-win-off risk)" HIGH
is "scale set at capacity 0 still LOW when protected" "$(col "$WORK/sched/machines.tsv" web-vmss risk)" LOW
is "disconnected Arc machine unchanged -> MEDIUM" "$(col "$WORK/sched/machines.tsv" arc-lnx risk)" MEDIUM
is "state column still shows the real state"  "$(col "$WORK/sched/machines.tsv" vm-win-off state)" deallocated

echo "-S (skip Defender settings)"
bash "$SCRIPT" -S -o "$WORK/skip" 2>/dev/null
is "integration unknown"                      "$(col "$WORK/skip/machines.tsv" vm-win-off mdeIntegration)" unknown
is "status falls back to 'no sensor'"         "$(col "$WORK/skip/machines.tsv" vm-win-off endpointProtection)" "NONE - Defender plan on, no sensor"

echo "Windows (Git Bash: CRLF output from az and jq, MSYS path rewriting)"
REAL_JQ=$(type -P jq) PATH="$HERE/mock-windows:$PATH" bash "$SCRIPT" -o "$WORK/win" 2>"$WORK/winlog"
if grep -q "Bad Request" "$WORK/winlog"; then
  bad "no 'Bad Request' errors"; grep -m3 "Bad Request" "$WORK/winlog"
else ok "no 'Bad Request' errors"; fi
for f in machines subscriptions; do
  if cmp -s "$WORK/out/$f.tsv" "$WORK/win/$f.tsv"; then ok "$f.tsv same as on Linux"; else bad "$f.tsv same as on Linux"; fi
done

echo "edr-summary.sh"
SUM="$HERE/../edr-summary.sh"
S="$WORK/sum"
bash "$SUM" -o "$S" "$WORK/out" 2>"$WORK/sumlog" && ok "summary exits 0" || { bad "summary exits 0"; cat "$WORK/sumlog"; }
R="$S/edr-report.md"; C="$S/edr-worklist.csv"
line() { if grep -qF -- "$2" "$3"; then ok "$1"; else bad "$1"; fi; }
line "report: machine counts"      "Machines: **11** (7 VMs, 2 scale sets, 2 Arc machines), of which active: **8**." "$R"
line "report: coverage"            "| Protected (EDR present) | 4 of 11 (36%) | 3 of 8 (38%) | 3 of 7 (43%) |" "$R"
line "report: risk table"          "| CRITICAL | 2 | 2 | 2 |" "$R"
line "report: OS names normalised" "| Linux | 6 | 5 | 4 |" "$R"
line "report: status table"        "| NONE - Defender plan on, MDE integration off | 2 | 0 | 1 | 1 |" "$R"
line "report: open ports"          "- Open ports: port 22: 2, port 3389: 2, port 5985: 1, port 5986: 1" "$R"
line "report: Defender plans"      "| Standard P2 | 1 | 1 | 1 | 1 |" "$R"
line "report: worklist counts"     "| HIGH | 6 |" "$R"
if ! grep -qE "vm-|aks-|arc-|203\.0\.113|prod-app|Tenant Root|11111111" "$R"; then ok "report: no names, IDs or IPs"; else bad "report: no names, IDs or IPs"; fi
if [[ "$(head -c3 "$C" | od -An -tx1 | tr -d ' ')" == efbbbf ]]; then ok "worklist: UTF-8 BOM for Excel"; else bad "worklist: UTF-8 BOM for Excel"; fi
line "worklist: machine columns"   '"item_id","severity","priority","category","issue","action","kind","machine","subscription"' "$C"
is "worklist: 12 items"            "$(($(wc -l < "$C") - 1))" 12
line "worklist: critical machine"  '"EDR-CRITICAL:/subscriptions/11111111-0000-0000-0000-000000000001/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-lnx-exposed","CRITICAL","1"' "$C"
line "worklist: IPs and ports"     '"203.0.113.10","22"' "$C"
line "worklist: subscription item" '"SUB-MDE-OFF:11111111-0000-0000-0000-000000000003","HIGH","2"' "$C"
line "worklist: AKS item"          '"EDR-AKS:' "$C"
line "worklist: other EDR to verify" '"EDR-OTHER-VERIFY:' "$C"
bash "$SUM" -s ';' -o "$WORK/sum2" "$WORK/out" 2>/dev/null
line "-s ';' separator"            '"CRITICAL";"1";"EDR-CRITICAL"' "$WORK/sum2/edr-worklist.csv"
if ! bash "$SUM" "$WORK/nonexistent" >/dev/null 2>&1; then ok "rejects a folder without inventory"; else bad "rejects a folder without inventory"; fi

echo "edr-summary.sh at scale"
mkdir -p "$WORK/big/raw"
jq -c 'range(0; 1000) as $i | . + {id: "\(.id)-\($i)", name: "\(.name)-\($i)"}' "$WORK/out/raw/model.jsonl" > "$WORK/big/raw/model.jsonl"
cp "$WORK/out/subscriptions.tsv" "$WORK/big/"
if bash "$SUM" "$WORK/big" >/dev/null 2>"$WORK/biglog"; then ok "11 000 machines: no 'argument list too long'"; else bad "11 000 machines: no 'argument list too long'"; cat "$WORK/biglog"; fi
is "  ... all items written" "$(($(wc -l < "$WORK/big/edr-worklist.csv") - 1))" 9003

echo "argument checks"
if ! bash "$SCRIPT" -s not-a-guid >/dev/null 2>&1; then ok "rejects a malformed subscription ID"; else bad "rejects a malformed subscription ID"; fi
if ! bash "$SCRIPT" -p "22,3389" >/dev/null 2>&1; then ok "rejects a malformed port list"; else bad "rejects a malformed port list"; fi
if bash "$SCRIPT" -h | grep -q "READ-ONLY inventory"; then ok "-h prints help"; else bad "-h prints help"; fi

echo "portability"
if ! (cd "$HERE/.." && grep -nE '(fromdateiso8601|fromdate|strptime|mktime|strftime|todate|dateadd)\b' azure-edr-inventory.sh edr-summary.sh | grep -v '^[^:]*:[0-9]*:[[:space:]]*#'); then
  ok "no jq date built-ins (missing in some Windows jq builds)"
else bad "no jq date built-ins (missing in some Windows jq builds)"; fi
echo
echo "$pass passed, $fail failed"
((fail == 0))
