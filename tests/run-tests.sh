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
bash "$SUM" "$WORK/out" > "$WORK/sum.md" 2>"$WORK/sumlog" && ok "summary exits 0" || { bad "summary exits 0"; cat "$WORK/sumlog"; }
has_line() { if grep -qF -- "$2" "$WORK/$3"; then ok "$1"; else bad "$1"; fi; }
has_line "machine counts"          "Machines: **11** (7 VMs, 2 scale sets, 2 Arc machines), of which active: **8**." sum.md
has_line "coverage"                "| Protected (EDR present) | 4 of 11 (36%) | 3 of 8 (38%) | 3 of 7 (43%) |" sum.md
has_line "risk table"              "| CRITICAL | 2 | 2 | 2 |" sum.md
has_line "OS names normalised"     "| Linux | 6 | 5 | 4 |" sum.md
has_line "status table"            "| NONE - Defender plan on, MDE integration off | 2 | 0 | 1 | 1 |" sum.md
has_line "open ports"              "- Open ports: port 22: 2, port 3389: 2, port 5985: 1, port 5986: 1" sum.md
has_line "Defender plans"          "| Standard P2 | 1 | 1 | 1 | 1 |" sum.md
if ! grep -qE "vm-|203\.0\.113|prod-app|Tenant Root" "$WORK/sum.md"; then ok "no names or IPs without -n"; else bad "no names or IPs without -n"; fi
bash "$SUM" -n "$WORK/out" > "$WORK/sumn.md" 2>/dev/null
has_line "-n lists CRITICAL machines" "| CRITICAL | vm-lnx-exposed | VM | prod-app | Linux | NONE - Defender plan on, no sensor | 203.0.113.10 | 22 |" sumn.md
has_line "-n lists subscriptions"  "| dev | Free |  | 1 | 2 | 1 |" sumn.md
if ! bash "$SUM" "$WORK/nonexistent" >/dev/null 2>&1; then ok "rejects a folder without inventory"; else bad "rejects a folder without inventory"; fi

echo "argument checks"
if ! bash "$SCRIPT" -s not-a-guid >/dev/null 2>&1; then ok "rejects a malformed subscription ID"; else bad "rejects a malformed subscription ID"; fi
if ! bash "$SCRIPT" -p "22,3389" >/dev/null 2>&1; then ok "rejects a malformed port list"; else bad "rejects a malformed port list"; fi
if bash "$SCRIPT" -h | grep -q "READ-ONLY inventory"; then ok "-h prints help"; else bad "-h prints help"; fi

echo
echo "$pass passed, $fail failed"
((fail == 0))
