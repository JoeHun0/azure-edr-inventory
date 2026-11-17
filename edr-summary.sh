#!/usr/bin/env bash
# edr-summary.sh - turns an azure-edr-inventory output folder into two files:
#
#   edr-report.md     counts only, no machine, subscription or management-group names
#                     and no IP addresses - safe to put into a report: coverage,
#                     protection status by OS, internet exposure, Defender for Servers
#                     plans, what to fix first
#   edr-worklist.csv  one row per thing to fix (machines and subscriptions), with names,
#                     IPs, details and what to do - internal. item_id (category:resource ID
#                     or subscription ID) stays the same between runs, so the file can feed
#                     a tracking spreadsheet (Excel: Data > From Text/CSV) and statuses kept
#                     there survive a refresh.
#
# Usage:
#   ./edr-summary.sh <output folder>           writes both files into that folder
#   ./edr-summary.sh -o <dir> <output folder>  writes them into <dir> instead
#   ./edr-summary.sh -s ';' <output folder>    CSV separator (default ","; use ";" if Excel
#                                              with a Hungarian or German locale opens it)
#
# Reads raw/model.jsonl and subscriptions.tsv from the folder. Needs only jq; no Azure access.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/azure-edr-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

SEP=","
OUT=""
while getopts ":s:o:h" opt; do
  case "$opt" in
    s) SEP="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
(($# == 1)) || die "give one azure-edr-inventory output folder (-h for help)"
[[ "$SEP" == "," || "$SEP" == ";" || "$SEP" == $'\t' ]] || die "-s must be , or ; or a tab"
DIR="$1"
[[ -f "$DIR/raw/model.jsonl" && -s "$DIR/subscriptions.tsv" ]] \
  || die "$DIR/raw/model.jsonl or $DIR/subscriptions.tsv not found - is this an azure-edr-inventory output folder?"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
jq() { command jq "$@" | tr -d '\r'; }   # Windows jq ends lines with CRLF

OUT=${OUT:-$DIR}
umask 077
mkdir -p "$OUT" || die "cannot create $OUT"
DETECTED=$(date -r "$DIR/raw/model.jsonl" +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)

# ---------------------------------------------------------------- shared jq
read -r -d '' JQ_PRE <<'JQ'
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def unprotected: startswith("NONE") or . == "AV ONLY" or test("failed");
def pct($n; $of): if $of == 0 then "-" else "\(($n * 100 / $of) | round)%" end;
def status: if startswith("OTHER EDR") then "OTHER EDR" else . end;
def cnt(f): map(select(f)) | length;
def num: tonumber? // 0;
def os: (.osType // "unknown") | ascii_downcase | if . == "windows" then "Windows" elif . == "linux" then "Linux" else . end;
def fix: if . == "NONE - Defender plan on, no sensor" then
           "Defender for Servers is on but no sensor was deployed: check OS and kernel support and the MDE extension, or onboard the machine manually."
         elif . == "NONE - Defender plan on, MDE integration off" then
           "Turn on the Defender for Endpoint integration in the subscription's Defender for Servers settings."
         elif . == "MDE - extension failed" then
           "Fix the failed MDE extension (check its status and logs; often an unsupported OS or kernel) and redeploy it."
         elif . == "AV ONLY" then
           "Antivirus only: deploy an EDR (Defender for Endpoint or the company EDR)."
         else
           "Enable Defender for Servers on the subscription (through Azure Policy) or deploy the company EDR."
         end;

($subs | split("\n") | map(select(length > 0) | split("\t"))) as $rows
| ($rows[0]) as $h
| [$rows[1:][] | [$h, .] | transpose | map({key: .[0], value: .[1]}) | from_entries] as $S
| $m as $M
JQ

# ---------------------------------------------------------------- worklist rows
read -r -d '' JQ_ROWS <<'JQ'
| def item($sev; $cat; $issue; $action; $details):
    {sev: $sev, cat: $cat, issue: $issue, action: $action, details: $details};
  "First check the EDR console: agents installed without a VM extension (GPO, Intune, scripts) show as unprotected here." as $check
| [ ( $M[] | . as $x
      | ( (if .risk == 4 then
             item(4; "EDR-CRITICAL"; "No EDR, running, and management ports open to the internet";
               "Close the management ports now (Azure Bastion or just-in-time access), then deploy EDR and check the machine for signs of compromise.";
               "\(.edr | fix) \($check)")
           else empty end),
          (if (.openPorts | length) > 0 and .risk != 4 then
             item(3; "EDR-EXPOSED"; "Management ports open to the internet";
               "Close the ports; use Azure Bastion or just-in-time VM access instead.";
               (if (.edr | unprotected) then "Also unprotected: \(.edr | fix)" else "" end))
           else empty end),
          (if (.edr | unprotected) and .active and (.aks | not) and (.openPorts | length) == 0 then
             item(3; "EDR-MISSING"; "No EDR on a running machine"; (.edr | fix); $check)
           else empty end),
          (if (.edr | unprotected) and ((.active | not) or .aks) and (.openPorts | length) == 0 then
             (if .aks then
                # covered by the per-cluster items below, except where the cluster wasn't found
                # (or the run is older than the Defender for Containers check)
                (if .edr == "NONE - orphaned AKS node pool" then
                   item(3; "EDR-AKS-ORPHAN"; "Orphaned AKS node pool: its cluster no longer exists";
                     "Confirm the cluster was deleted, then remove the leftover scale set and node resource group: nothing maintains or protects it. If it is still in use, put it under an owner and protect it.";
                     "")
                 elif ($aks | length) == 0 then
                   item(2; "EDR-AKS"; "AKS node pool without Defender for Containers coverage";
                     "Find the node pool's AKS cluster and check that Defender for Containers covers it (plan on for the subscription, sensor on for the cluster).";
                     "")
                 else empty end)
              else
                item(2; "EDR-MISSING-INACTIVE"; "No EDR on a stopped or disconnected machine";
                  "Deploy the EDR before the machine is started or reconnected, or delete it if it's no longer needed.";
                  (.edr | fix))
              end)
           else empty end),
          (if (.edr | startswith("OTHER EDR")) then
             item(1; "EDR-OTHER-VERIFY"; "Another vendor's EDR agent";
               "Confirm the agent is healthy and reports to the SOC's console.";
               "")
           else empty end)
        )
      | . + {x: $x, kind: "machine"} ),
    ( $S[]
      | . as $s
      | ( (if .defenderTier != "Standard" and (.unprotectedActive | num) > 0 then
             item(3; "SUB-NO-DEFENDER"; "Defender for Servers off, with unprotected running machines";
               "Enable Defender for Servers (P1; P2 for internet-facing and critical servers), preferably through Azure Policy at management-group level, or confirm the company EDR covers these machines.";
               "Unprotected active machines: \(.unprotectedActive).")
           else empty end),
          (if .mdeIntegration == "false" then
             item(3; "SUB-MDE-OFF"; "Defender for Servers on, but the Defender for Endpoint integration is off";
               "Turn on the integration: Defender for Cloud > Environment settings > the subscription > Settings & monitoring.";
               "Unprotected active machines: \(.unprotectedActive).")
           else empty end)
        )
      | . + {s: $s, kind: "subscription"} ),
    ( $aks[] | select(.status != "DEFENDER FOR CONTAINERS") | . as $c
      | (if ((.power // "") | ascii_downcase) == "stopped" then 2 else 3 end) as $sev
      | (if .status == "NONE - no Defender for Containers" then
           item($sev; "AKS-NO-CONTAINERS"; "AKS cluster without Defender for Containers";
             "Enable Defender for Containers on the subscription (preferably through Azure Policy at management-group level) with automatic sensor provisioning, then check that the sensor runs on the cluster.";
             "Node pools: \(.nodePools).")
         else
           item($sev; "AKS-SENSOR-OFF"; "Defender for Containers is on, but the sensor isn't deployed to the cluster";
             "Enable the Defender sensor on the cluster (az aks update --enable-defender, or automatic sensor provisioning in the plan settings) and check that the sensor pods run.";
             "Automatic sensor provisioning in the plan: \(if .planSensorProvisioning then "on" else "off" end). Node pools: \(.nodePools).")
         end)
      | . + {c: $c, kind: "cluster"} )
  ]
| sort_by(-.sev, .cat, (.x.subscription // .s.subscription // .c.subscription // ""), (.x.name // .c.name // ""))
JQ

# ---------------------------------------------------------------- CSV
read -r -d '' JQ_CSV <<'JQ'
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def csvrow: map(if . == null then "" else tostring end
                | if test("^[=+\\-@\t\r]") then "'" + . else . end   # no formulas in Excel
                | gsub("\""; "\"\"") | "\"" + . + "\"") | join($sep);
. as $rows
| (["item_id", "severity", "priority", "category", "issue", "action", "kind", "machine", "subscription",
  "subscription_id", "resource_group", "location", "os", "os_detail", "state", "protection",
  "defender_plan", "mde_integration", "public_ips", "open_ports", "aks_node_pool", "management_groups",
  "resource_id", "details", "detected"] | csvrow),
($rows[] | if .kind == "machine" then .x as $x
    | ["\(.cat):\($x.id | ascii_downcase)", (.sev | risklabel), (5 - .sev), .cat, .issue, .action, $x.kind,
       $x.name, $x.subscription, $x.subscriptionId, $x.resourceGroup, $x.location, $x.osType, $x.osDetail,
       $x.state, $x.edr, $x.plan, $x.mde, ($x.publicIps | join(", ")), ($x.openPorts | map(tostring) | join(", ")),
       (if $x.aks then "yes" else "no" end), $x.mgPath, $x.id, .details, $detected]
  elif .kind == "cluster" then .c as $c
    | ["\(.cat):\($c.id | ascii_downcase)", (.sev | risklabel), (5 - .sev), .cat, .issue, .action, "AKS cluster",
       $c.name, $c.subscription, $c.subscriptionId, $c.resourceGroup, $c.location, "", "Kubernetes \($c.version)",
       $c.power, $c.status, "Containers: \($c.containersPlan)", "", "", "", "", $c.mgPath, $c.id, .details, $detected]
  else .s as $s
    | ["\(.cat):\($s.subscriptionId)", (.sev | risklabel), (5 - .sev), .cat, .issue, .action, "Subscription",
       "", $s.subscription, $s.subscriptionId, "", "", "", "", $s.state, "",
       ("\($s.defenderTier) \($s.defenderSubPlan)" | rtrimstr(" ")), $s.mdeIntegration, "", "", "",
       $s.managementGroups, "/subscriptions/\($s.subscriptionId)", .details, $detected]
  end | csvrow)
JQ

# ---------------------------------------------------------------- report.md
read -r -d '' JQ_REPORT <<'JQ'
| ($M | length) as $n
| ($M | map(select(.active))) as $act
| "# Endpoint protection (EDR) on Azure servers",
  "",
  "Inventory of \($detected) (azure-edr-inventory). Counts only.",
  "",
  "> **About this data:** these numbers come straight from Azure Resource Graph and the Azure management API (the control plane), not from inside the machines. Treat them as indicative, not exact:",
  "> - an EDR installed without a VM extension (script, GPO, image) shows as missing;",
  "> - an installed extension doesn't prove a healthy, reporting sensor;",
  "> - internet exposure is a static reading of NSG rules: Azure Firewall, NVAs, load balancer NAT rules and service tags are not considered;",
  "> - Resource Graph can lag a few minutes behind recent changes.",
  ">",
  "> Confirm individual machines in the EDR console and with Network Watcher before acting on them.",
  "",
  ( if $scope.rootAccess == false then
      "> **Warning: incomplete inventory.** The account that ran it couldn't read the tenant root management group (no Reader role there, or a PIM role that wasn't active), so only the \($scope.subscriptions) subscription(s) it could see are covered. Re-run with the role active.",
      ""
    elif $scope.subscriptionFilter == true then
      "> Limited to selected subscriptions (`-s`).", ""
    else empty end ),
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
    | "| \(if .[0].defenderTier == "Standard" then "Standard \(.[0].defenderSubPlan // "")" | rtrimstr(" ") else (.[0].defenderTier // "unknown") end) | \(length) | \(cnt((.machines | num) > 0)) | \(cnt(.mdeIntegration == "false")) | \(map(.unprotectedActive | num) | add) |" ),
  "",
  ( if ($aks | length) > 0 then
      "## Defender for Containers (AKS)",
      "",
      "AKS nodes are protected by Defender for Containers, not Defender for Servers: the plan has to be on for the subscription and the sensor deployed to the cluster.",
      "",
      "| Status | Clusters | Node pools |", "|---|---|---|",
      ( $aks | group_by(.status) | sort_by(-length)[] | "| \(.[0].status) | \(length) | \(map(.nodePools) | add) |" ),
      "",
      ( [$aks[] | .subscriptionId | ascii_downcase] | unique | length ) as $as
      | ( [$aks[] | select(.containersPlan != "Standard") | .subscriptionId | ascii_downcase] | unique | length ) as $off
      | "- Subscriptions with AKS clusters: **\($as)**, of which without Defender for Containers: **\($off)**",
      "- Orphaned AKS node pools (the scale set carries AKS's node-pool tag, but its cluster no longer exists): **\($M | cnt(.edr == "NONE - orphaned AKS node pool"))**",
      ""
    else empty end ),
  "## Other",
  "",
  ( if ($aks | length) > 0 then
      "- AKS node pools without Defender for Containers coverage: **\($M | cnt(.aks and (.edr | unprotected)))** of \($M | cnt(.aks))"
    else
      "- Unprotected AKS node pools: **\($M | cnt(.aks and (.edr | unprotected)))** (Defender for Containers coverage not checked in this run)"
    end ),
  "- Arc machines not connected: **\($M | cnt(.kind == "Arc" and (.active | not)))**",
  "- Failed MDE extensions: **\($M | cnt(.edr | test("failed")))**",
  "- Machines only on antivirus (Microsoft Antimalware, no EDR): **\($M | cnt(.edr == "AV ONLY"))**",
  "",
  "## Fix first",
  "",
  "1. CRITICAL machines (unprotected, running, management ports open to the internet): **\($M | cnt(.risk == 4))**. Close the ports (Bastion or JIT), deploy EDR, check for compromise.",
  "2. Other machines with management ports open to the internet: **\($M | cnt((.openPorts | length > 0) and (.risk != 4)))**. Close the ports.",
  "3. Subscriptions without Defender for Servers that have unprotected active machines: **\($S | cnt(.defenderTier != "Standard" and ((.unprotectedActive | num) > 0)))**. Subscriptions with the plan on but the MDE integration off: **\($S | cnt(.mdeIntegration == "false"))**. Enable both through Azure Policy at management-group level.",
  ( if ($aks | length) > 0 then
      "4. AKS clusters not covered by Defender for Containers: **\($aks | cnt(.status != "DEFENDER FOR CONTAINERS"))**. Turn on the plan and the sensor."
    else empty end ),
  "",
  "Agents installed inside the OS without a VM extension (GPO, Intune, scripts) show as unprotected here. Check those machines against the EDR console before acting.",
  "",
  "## Worklist",
  "",
  "| Severity | Items |", "|---|---|",
  ($items[0] | map(.sev) | group_by(.) | reverse
   | if length == 0 then "| (none) | |" else .[] | "| \(.[0] | risklabel) | \(length) |" end)
JQ

SCOPE=$(cat "$DIR/raw/scope.json" 2>/dev/null || echo '{}')   # absent in runs made before it existed
AKSF="$DIR/raw/aks_model.jsonl"; [[ -f "$AKSF" ]] || AKSF=/dev/null   # likewise
ARGS=(--slurpfile m "$DIR/raw/model.jsonl" --rawfile subs "$DIR/subscriptions.tsv" --arg detected "$DETECTED"
      --argjson scope "$SCOPE" --slurpfile aks "$AKSF")
# The rows go through a file: as a command-line argument they would hit the OS limit
# (128 KB per argument on Linux, 32 KB per command line on Windows).
ITEMS=$(mktemp) || die "cannot create a temporary file"
trap 'rm -f "$ITEMS"' EXIT
jq -n -c "${ARGS[@]}" "$JQ_PRE $JQ_ROWS" > "$ITEMS" || die "building the worklist failed"
{ printf '\xEF\xBB\xBF'; jq -r --arg sep "$SEP" --arg detected "$DETECTED" "$JQ_CSV" < "$ITEMS"; } \
  > "$OUT/edr-worklist.csv" || die "writing edr-worklist.csv failed"
jq -n -r "${ARGS[@]}" --slurpfile items "$ITEMS" "$JQ_PRE $JQ_REPORT" > "$OUT/edr-report.md" \
  || die "building edr-report.md failed"

printf 'edr-report.md     %s  (counts only - safe for the report)\n' "$OUT/edr-report.md" >&2
printf 'edr-worklist.csv  %s  (%s items, with names and IPs - internal)\n' "$OUT/edr-worklist.csv" "$(jq -r 'length' < "$ITEMS")" >&2
