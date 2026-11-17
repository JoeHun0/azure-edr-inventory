#!/usr/bin/env bash
# edr-summary.sh - turns an azure-edr-inventory output folder into a short summary in
# Markdown: coverage, endpoint protection status, internet exposure, OS split, Defender
# for Servers plans per subscription, and what to fix first.
#
# Usage:
#   ./edr-summary.sh <output folder>      counts only - safe to paste into a report
#   ./edr-summary.sh -n <output folder>   also list the CRITICAL and HIGH machines and
#                                         the subscriptions to fix (internal use)
#
# Reads raw/model.jsonl and subscriptions.tsv from the folder. Needs only jq; no Azure access.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/azure-edr-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

NAMES=0
while getopts ":nh" opt; do
  case "$opt" in
    n) NAMES=1 ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
(($# == 1)) || die "give one azure-edr-inventory output folder (-h for help)"
DIR="$1"
[[ -f "$DIR/raw/model.jsonl" && -s "$DIR/subscriptions.tsv" ]] \
  || die "$DIR/raw/model.jsonl or $DIR/subscriptions.tsv not found - is this an azure-edr-inventory output folder?"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
jq() { command jq "$@" | tr -d '\r'; }   # Windows jq ends lines with CRLF

jq -n -r --slurpfile m "$DIR/raw/model.jsonl" --rawfile subs "$DIR/subscriptions.tsv" \
  --argjson names "$NAMES" --arg dir "$DIR" '
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def unprotected: startswith("NONE") or . == "AV ONLY" or test("failed");
def pct($n; $of): if $of == 0 then "-" else "\(($n * 100 / $of) | round)%" end;
def status: if startswith("OTHER EDR") then "OTHER EDR" else . end;
def cnt(f): map(select(f)) | length;
def os: (.osType // "unknown") | ascii_downcase | if . == "windows" then "Windows" elif . == "linux" then "Linux" else . end;

($subs | split("\n") | map(select(length > 0) | split("\t"))) as $rows
| ($rows[0]) as $h
| [$rows[1:][] | [$h, .] | transpose | map({key: .[0], value: .[1]}) | from_entries] as $S
| $m as $M
| ($M | length) as $n
| ($M | map(select(.active))) as $act
| ($M | map(select(.edr | unprotected))) as $unp
| (
  "# azure-edr-inventory summary",
  "",
  "Source: `\($dir)`. Generated \(now | strftime("%Y-%m-%d %H:%M")) UTC.",
  "",
  "Machines: **\($n)** (\($M | cnt(.kind == "VM")) VMs, \($M | cnt(.kind == "VMSS")) scale sets, \($M | cnt(.kind == "Arc")) Arc machines), of which active: **\($act | length)**.",
  "Subscriptions: **\($S | length)**.",
  "",
  "## Coverage",
  "",
  "| | All machines | Active machines | Active, without AKS node pools |",
  "|---|---|---|---|",
  ( ($M | map(select(.aks | not)) | map(select(.active))) as $actNoAks
    | "| Protected (EDR present) | \($M | cnt(.edr | unprotected | not)) of \($n) (\(pct($M | cnt(.edr | unprotected | not); $n))) | \($act | cnt(.edr | unprotected | not)) of \($act | length) (\(pct($act | cnt(.edr | unprotected | not); $act | length))) | \($actNoAks | cnt(.edr | unprotected | not)) of \($actNoAks | length) (\(pct($actNoAks | cnt(.edr | unprotected | not); $actNoAks | length))) |" ),
  "",
  "## By risk",
  "",
  "| Risk | Machines | Active | Management ports open to the internet |",
  "|---|---|---|---|",
  ( [4, 3, 2, 1][] as $r | ($M | map(select(.risk == $r))) as $g
    | "| \($r | risklabel) | \($g | length) | \($g | cnt(.active)) | \($g | cnt(.openPorts | length > 0)) |" ),
  "",
  "## Endpoint protection status",
  "",
  "| Status | Machines | Active | Windows | Linux |",
  "|---|---|---|---|---|",
  ( $M | group_by(.edr | status) | sort_by(-length)[]
    | "| \(.[0].edr | status) | \(length) | \(cnt(.active)) | \(cnt(os == "Windows")) | \(cnt(os == "Linux")) |" ),
  "",
  ( [$M[] | select(.edr | startswith("OTHER EDR")) | .edr | sub("^OTHER EDR: "; "")] | group_by(.)
    | if length > 0 then "Other EDR agents found: " + (map("\(.[0]) (\(length))") | join(", ")) + ".", "" else empty end ),
  "## By operating system",
  "",
  "| OS | Machines | Unprotected | Unprotected and active |",
  "|---|---|---|---|",
  ( $M | group_by(os) | .[]
    | "| \(.[0] | os) | \(length) | \(cnt(.edr | unprotected)) | \(cnt((.edr | unprotected) and .active)) |" ),
  "",
  "## Internet exposure (VMs)",
  "",
  "- VMs with a public IP: **\($M | cnt(.publicIps | length > 0))**",
  "- VMs with management ports open to the internet: **\($M | cnt(.openPorts | length > 0))**, of which unprotected: **\($M | cnt((.openPorts | length > 0) and (.edr | unprotected)))**",
  ( [$M[] | .openPorts[]] | group_by(.) | map("port \(.[0]): \(length)") | if length > 0 then "- Open ports: " + join(", ") else empty end ),
  "",
  "## Defender for Servers (subscriptions)",
  "",
  "| Plan | Subscriptions | With machines | MDE integration off | Unprotected active machines |",
  "|---|---|---|---|---|",
  ( $S | group_by(if .defenderTier == "Standard" then "Standard \(.defenderSubPlan // "")" | rtrimstr(" ") else (.defenderTier // "unknown") end)[]
    | "| \(if .[0].defenderTier == "Standard" then "Standard \(.[0].defenderSubPlan // "")" | rtrimstr(" ") else (.[0].defenderTier // "unknown") end) | \(length) | \(cnt((.machines | tonumber? // 0) > 0)) | \(cnt(.mdeIntegration == "false")) | \(map(.unprotectedActive | tonumber? // 0) | add) |" ),
  "",
  "## Other",
  "",
  "- Unprotected AKS node pools: **\($M | cnt(.aks and (.edr | unprotected)))** (usually covered by Defender for Containers instead)",
  "- Arc machines not connected: **\($M | cnt(.kind == "Arc" and (.active | not)))**",
  "- Failed MDE extensions: **\($M | cnt(.edr | test("failed")))**",
  "- Machines only on antivirus (Microsoft Antimalware, no EDR): **\($M | cnt(.edr == "AV ONLY"))**",
  "",
  "## Fix first",
  "",
  "1. CRITICAL machines (unprotected, running, management ports open to the internet): **\($M | cnt(.risk == 4))**. Close the ports (Bastion or JIT), deploy EDR, check for compromise.",
  "2. Other machines with management ports open to the internet: **\($M | cnt((.openPorts | length > 0) and (.risk != 4)))**. Close the ports.",
  "3. Subscriptions without Defender for Servers that have unprotected active machines: **\($S | cnt(.defenderTier != "Standard" and ((.unprotectedActive | tonumber? // 0) > 0)))**. Subscriptions with the plan on but the MDE integration off: **\($S | cnt(.mdeIntegration == "false"))**. Enable both through Azure Policy at management-group level.",
  "",
  "Agents installed inside the OS without a VM extension (GPO, Intune, scripts) show as unprotected here. Check those machines against the EDR console before acting.",
  ( if $names == 1 then
      "",
      "## CRITICAL and HIGH machines (internal - contains names and IPs)",
      "",
      "| Risk | Machine | Kind | Subscription | OS | Status | Public IPs | Open ports |",
      "|---|---|---|---|---|---|---|---|",
      ( $M | map(select(.risk >= 3)) | sort_by(-.risk, .subscription, .name)[]
        | "| \(.risk | risklabel) | \(.name) | \(.kind) | \(.subscription) | \(os) | \(.edr) | \(.publicIps | join(", ")) | \(.openPorts | map(tostring) | join(", ")) |" ),
      "",
      "## Subscriptions to fix (internal - contains names)",
      "",
      "| Subscription | Defender plan | MDE integration | Unprotected active | Exposed | Critical |",
      "|---|---|---|---|---|---|",
      ( $S | map(select((.unprotectedActive | tonumber? // 0) > 0 or (.internetMgmtPortsOpen | tonumber? // 0) > 0))
        | sort_by(-(.critical | tonumber? // 0), -(.unprotectedActive | tonumber? // 0))[]
        | "| \(.subscription) | \("\(.defenderTier) \(.defenderSubPlan)" | rtrimstr(" ")) | \(.mdeIntegration) | \(.unprotectedActive) | \(.internetMgmtPortsOpen) | \(.critical) |" )
    else empty end )
)'
