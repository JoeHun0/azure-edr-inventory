#!/usr/bin/env bash
# azure-edr-inventory.sh - READ-ONLY inventory of endpoint protection (EDR / AV)
# coverage on servers in Azure: virtual machines, scale sets and Azure Arc machines.
#
# For every machine in every subscription of the tenant it reports:
#   * OS, power / connection state, scale set capacity, AKS node pools
#   * security agents installed as extensions: Microsoft Defender for Endpoint
#     (MDE.Windows / MDE.Linux), other EDR vendors, Microsoft Antimalware (AV only)
#   * the subscription's Microsoft Defender for Servers plan (Free / P1 / P2) and
#     whether its Defender for Endpoint integration is switched on
#   * internet exposure: public IPs and NSG rules that open management ports
#     (default 22, 3389, 5985, 5986) to the internet
# and a risk rating per machine (a heuristic - verify by hand).
#
# Only read operations are used (az graph query, az rest --method GET).
# Nothing in the tenant is changed.
#
# Needs: az CLI logged in (az login), the resource-graph extension
#        (az extension add --name resource-graph), jq 1.6+.
#        Reader (or more) on the tenant root management group; for the
#        Defender settings also Security Reader (Reader is usually enough).
#
# Usage:
#   ./azure-edr-inventory.sh                  whole tenant
#   ./azure-edr-inventory.sh -s <subId> ...   only these subscriptions (-s can be repeated)
#   ./azure-edr-inventory.sh -p "22 3389"     management ports to check (default "22 3389 5985 5986")
#   ./azure-edr-inventory.sh -S               skip the per-subscription Defender settings calls
#   ./azure-edr-inventory.sh -o <dir>         output folder
#                                             (default ./edr-inventory-YYYYMMDD-HHMM)
#
# Output (tab-separated, opens in LibreOffice Calc / Excel):
#   machines.tsv       one row per machine, highest risk first
#   subscriptions.tsv  Defender for Servers plan and coverage per subscription
#   raw/               the raw JSON lines the reports are built from
# The output lists unprotected and internet-exposed servers: keep it private.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/azure-edr-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

SUBS=()
PORTS="22 3389 5985 5986"
SKIP_SETTINGS=0
OUTDIR=""
while getopts ":s:p:So:h" opt; do
  case "$opt" in
    s) SUBS+=("$OPTARG") ;;
    p) PORTS="$OPTARG" ;;
    S) SKIP_SETTINGS=1 ;;
    o) OUTDIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

GUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
for s in "${SUBS[@]}"; do
  [[ "$s" =~ $GUID_RE ]] || die "not a subscription ID: $s"
done
[[ "$PORTS" =~ ^[0-9]+( [0-9]+)*$ ]] || die "-p takes space-separated port numbers, e.g. \"22 3389\""

command -v az >/dev/null || die "az CLI not found"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
az extension show --name resource-graph --only-show-errors >/dev/null 2>&1 \
  || die "resource-graph extension missing: az extension add --name resource-graph"
TENANT_ID=$(az account show --query tenantId -o tsv --only-show-errors </dev/null 2>/dev/null) \
  && [[ -n "$TENANT_ID" ]] || die "not logged in: run az login"

umask 077
OUTDIR=${OUTDIR:-"./edr-inventory-$(date +%Y%m%d-%H%M)"}
RAW="$OUTDIR/raw"
mkdir -p "$RAW" || die "cannot create $RAW"

ARM="https://management.azure.com"

# Azure Resource Graph query over the whole tenant (root management group),
# with paging; prints .data[] as JSON lines.
arg_all() {
  local q="$1" skip="" resp
  local args=(graph query -q "$q" --management-groups "$TENANT_ID" --first 1000 -o json --only-show-errors)
  while :; do
    if [[ -n "$skip" ]]; then
      resp=$(az "${args[@]}" --skip-token "$skip" </dev/null) || return 1
    else
      resp=$(az "${args[@]}" </dev/null) || return 1
    fi
    jq -c '.data[]?' <<<"$resp" || return 1
    skip=$(jq -r '.skip_token // empty' <<<"$resp")
    [[ -z "$skip" ]] && break
  done
}

# run_arg <name> <description> <query>  ->  $RAW/<name>.jsonl
run_arg() {
  log "Reading $2..."
  arg_all "$3" > "$RAW/$1.jsonl" || warn "Resource Graph query for $2 failed - report will be incomplete"
}

# ---------------------------------------------------------------- 1. Resource Graph
run_arg subs "subscriptions" "resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, state = tostring(properties.state), mgChain = properties.managementGroupAncestorsChain"

run_arg pricing "Defender for Servers plans" "securityresources
| where type =~ 'microsoft.security/pricings' and name =~ 'VirtualMachines'
| project subscriptionId, tier = tostring(properties.pricingTier), subPlan = tostring(properties.subPlan)"

run_arg vms "virtual machines" "resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id = tolower(id), name, subscriptionId, resourceGroup, location,
          osType = tostring(properties.storageProfile.osDisk.osType),
          osName = tostring(properties.extended.instanceView.osName),
          osVersion = tostring(properties.extended.instanceView.osVersion),
          image = strcat(tostring(properties.storageProfile.imageReference.publisher), '/',
                         tostring(properties.storageProfile.imageReference.offer), '/',
                         tostring(properties.storageProfile.imageReference.sku)),
          power = tostring(properties.extended.instanceView.powerState.code),
          nics = properties.networkProfile.networkInterfaces"

run_arg vmext "virtual machine extensions" "resources
| where type =~ 'microsoft.compute/virtualmachines/extensions'
| project machineId = tolower(tostring(split(id, '/extensions/')[0])),
          publisher = tostring(properties.publisher), extType = tostring(properties.type),
          state = tostring(properties.provisioningState)"

run_arg vmss "virtual machine scale sets" "resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| project id = tolower(id), name, subscriptionId, resourceGroup, location,
          osType = tostring(properties.virtualMachineProfile.storageProfile.osDisk.osType),
          image = strcat(tostring(properties.virtualMachineProfile.storageProfile.imageReference.publisher), '/',
                         tostring(properties.virtualMachineProfile.storageProfile.imageReference.offer), '/',
                         tostring(properties.virtualMachineProfile.storageProfile.imageReference.sku)),
          capacity = toint(sku.capacity),
          extensions = properties.virtualMachineProfile.extensionProfile.extensions,
          aks = isnotempty(tostring(tags['aks-managed-poolName'])) or tolower(resourceGroup) startswith 'mc_'"

run_arg arc "Azure Arc machines" "resources
| where type =~ 'microsoft.hybridcompute/machines'
| project id = tolower(id), name, subscriptionId, resourceGroup, location,
          osType = tostring(properties.osType), osName = tostring(properties.osSku),
          osVersion = tostring(properties.osVersion), status = tostring(properties.status)"

run_arg arcext "Azure Arc machine extensions" "resources
| where type =~ 'microsoft.hybridcompute/machines/extensions'
| project machineId = tolower(tostring(split(id, '/extensions/')[0])),
          publisher = tostring(properties.publisher), extType = tostring(properties.type),
          state = tostring(properties.provisioningState)"

run_arg nics "network interfaces" "resources
| where type =~ 'microsoft.network/networkinterfaces'
| project id = tolower(id), nsgId = tolower(tostring(properties.networkSecurityGroup.id)),
          ipConfigs = properties.ipConfigurations"

run_arg pips "public IP addresses" "resources
| where type =~ 'microsoft.network/publicipaddresses'
| project id = tolower(id), ip = tostring(properties.ipAddress), sku = tostring(sku.name)"

run_arg nsgs "network security groups" "resources
| where type =~ 'microsoft.network/networksecuritygroups'
| project id = tolower(id), name, rules = properties.securityRules"

run_arg subnets "subnets" "resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet = properties.subnets
| project id = tolower(tostring(subnet.id)), nsgId = tolower(tostring(subnet.properties.networkSecurityGroup.id))"

# ---------------------------------------------------------------- 2. per-subscription Defender settings
in_scope() {  # in_scope <subscriptionId>: true when no -s was given or it was given
  ((${#SUBS[@]} == 0)) && return 0
  local s; for s in "${SUBS[@]}"; do [[ "${s,,}" == "${1,,}" ]] && return 0; done
  return 1
}

: > "$RAW/pricing_rest.jsonl"
: > "$RAW/mde_settings.jsonl"
mapfile -t ALL_SUBS < <(jq -r '.subscriptionId' "$RAW/subs.jsonl")
missing=0
for s in "${ALL_SUBS[@]}"; do
  in_scope "$s" || continue
  jq -e --arg s "$s" 'select(.subscriptionId == $s)' "$RAW/pricing.jsonl" >/dev/null && continue
  missing=$((missing + 1))
  az rest --method GET --url "$ARM/subscriptions/$s/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2023-01-01" \
      -o json --only-show-errors </dev/null 2>/dev/null \
    | jq -c --arg s "$s" '{subscriptionId: $s, tier: .properties.pricingTier, subPlan: (.properties.subPlan // "")}' \
    >> "$RAW/pricing_rest.jsonl" || true
done
((missing)) && log "Defender plan read directly for $missing subscription(s) missing from Resource Graph."

if ((SKIP_SETTINGS)); then
  log "Skipping Defender for Endpoint integration settings (-S)."
else
  mapfile -t STD_SUBS < <(jq -r -s 'map(select(.tier == "Standard")) | .[].subscriptionId' \
                            "$RAW/pricing.jsonl" "$RAW/pricing_rest.jsonl" | sort -u)
  n=0
  for s in "${STD_SUBS[@]}"; do
    in_scope "$s" || continue
    n=$((n + 1))
    v=$(az rest --method GET --url "$ARM/subscriptions/$s/providers/Microsoft.Security/settings/WDATP?api-version=2022-05-01" \
          --query properties.enabled -o tsv --only-show-errors </dev/null 2>/dev/null) || v="unknown"
    jq -c -n --arg s "$s" --arg v "${v:-unknown}" '{subscriptionId: $s, mde: ($v | ascii_downcase)}' >> "$RAW/mde_settings.jsonl"
  done
  log "Defender for Endpoint integration setting read for $n subscription(s) with Defender for Servers."
fi

# ---------------------------------------------------------------- 3. model
log "Building reports..."
SUBS_JSON=$(printf '%s\n' "${SUBS[@]}" | jq -R -s -c 'split("\n") | map(select(length > 0) | ascii_downcase)')
PORTS_JSON=$(jq -n -c --arg p "$PORTS" '$p | split(" ") | map(tonumber)')
OTHER_EDR='crowdstrike|sentinelone|trendmicro|deepsecurity|sophos|symantec|mcafee|trellix|bitdefender|eset|kaspersky|cylance|carbonblack|paloalto|cortex|cybereason|withsecure|f-secure|elastic.*(agent|endpoint)'

read -r -d '' JQ_MODEL <<'JQ'
def lc: ascii_downcase;
def bykey(k): map({key: (.[k] | tostring | lc), value: .}) | from_entries;
def nz: if . == null or . == "" then null else . end;

# --- NSG evaluation: does the first matching inbound rule from the internet allow TCP port $p?
def covers($p): if . == "*" then true
                elif test("^[0-9]+-[0-9]+$") then (split("-") | map(tonumber)) as [$a, $b] | ($p >= $a and $p <= $b)
                elif test("^[0-9]+$") then tonumber == $p
                else false end;
def from_internet: [(.sourceAddressPrefix // empty), (.sourceAddressPrefixes // [])[]]
                   | any(lc | IN("*", "internet", "0.0.0.0/0", "any", "::/0"));
def tcp: (.protocol // "*") | lc | IN("*", "tcp");
def dports: [(.destinationPortRange // empty), (.destinationPortRanges // [])[]];
def nsg_allows($rules; $p):
  [$rules[] | (.properties // .) | select(((.direction // "") | lc) == "inbound" and from_internet and tcp and (dports | any(covers($p))))]
  | sort_by(.priority) | .[0]
  | if . == null then false else ((.access // "") | lc) == "allow" end;

# --- exposure of a VM from its NICs: public IPs and management ports open to the internet
def exposure($nicIds; $nicBy; $pipBy; $nsgBy; $subnetBy; $ports):
  [ $nicIds[] | lc | $nicBy[.] // empty | . as $nic
    | ($nic.ipConfigs // [])[] | (.properties // .) as $cfg
    | ($cfg.publicIPAddress.id // "" | lc | nz) as $pipId
    | select($pipId != null)
    | ($pipBy[$pipId] // {ip: "", sku: ""}) as $pip
    | ([$nic.nsgId, ($subnetBy[$cfg.subnet.id // "" | lc].nsgId // "")] | map(nz) | map(select(. != null))) as $nsgIds
    | { ip: (if ($pip.ip // "") == "" then "(dynamic, not allocated)" else $pip.ip end),
        open: [ $ports[] as $p
                | select(if ($nsgIds | length) == 0 then (($pip.sku // "") | lc) != "standard"
                         else all($nsgIds[]; nsg_allows(($nsgBy[.].rules // []); $p)) end)
                | $p ] } ]
  | {publicIps: (map(.ip) | unique), openPorts: (map(.open[]) | unique)};

# --- security agents from the extension list
def edr($exts; $plan; $mde; $other):
  ($exts | map({name: "\(.publisher).\(.extType)", type: .extType, state: (.state // "")})) as $e
  | ([$e[] | select(.type | IN("MDE.Windows", "MDE.Linux"))]) as $mdeExt
  | ([$e[] | select(.name | lc | test($other))] | map(.name) | unique) as $others
  | if ($mdeExt | length) > 0 then
      (if any($mdeExt[]; (.state | lc) == "failed") then "MDE - extension failed" else "MDE" end)
    elif ($others | length) > 0 then "OTHER EDR: " + ($others | join(", "))
    elif any($e[]; .name | lc | test("iaasantimalware")) then "AV ONLY"
    elif ($plan.tier // "") == "Standard" and $mde == "false" then "NONE - Defender plan on, MDE integration off"
    elif ($plan.tier // "") == "Standard" then "NONE - Defender plan on, no sensor"
    else "NONE" end;

def unprotected: startswith("NONE") or . == "AV ONLY" or test("failed");
def risk: (.edr | unprotected) as $u | (.openPorts | length > 0) as $o
  | if $u and $o and .active then 4
    elif $o and .active then 3
    elif $u and .active and (.aks | not) then 3
    elif $u then 2
    else 1 end;
def mgpath: [(. // [])[] | .displayName] | reverse | join(" / ");

($subs | bykey("subscriptionId")) as $subBy
| (($pricing + $pricingRest) | bykey("subscriptionId")) as $planBy
| ($mdeSettings | bykey("subscriptionId")) as $mdeBy
| (($vmext + $arcext) | group_by(.machineId) | map({key: .[0].machineId, value: .}) | from_entries) as $extBy
| ($nics | bykey("id")) as $nicBy
| ($pips | bykey("id")) as $pipBy
| ($nsgs | bykey("id")) as $nsgBy
| ($subnets | bykey("id")) as $subnetBy
| (
    [ $vms[] | {kind: "VM", id, name, subscriptionId, resourceGroup, location, osType,
                osDetail: (if (.osName // "") != "" then "\(.osName) \(.osVersion // "")" else .image end),
                state: ((.power // "") | sub("^PowerState/"; "") | if . == "" then "unknown" else . end),
                exts: ($extBy[.id] // []),
                nicIds: [(.nics // [])[] | .id], aks: false}
      | . + {active: (.state | IN("running", "starting", "unknown"))} ]
    + [ $vmss[] | {kind: "VMSS", id, name, subscriptionId, resourceGroup, location, osType, osDetail: .image,
                 state: "capacity \(.capacity // 0)", active: ((.capacity // 0) > 0),
                 exts: [(.extensions // [])[] | (.properties // .) | {publisher, extType: .type, state: ""}],
                 nicIds: [], aks: (.aks // false)} ]
    + [ $arc[] | {kind: "Arc", id, name, subscriptionId, resourceGroup, location, osType,
                osDetail: "\(.osName // "") \(.osVersion // "")", state: (.status // "unknown"),
                active: ((.status // "") == "Connected"), exts: ($extBy[.id] // []), nicIds: [], aks: false} ]
  )[]
| select(($scope | length) == 0 or (.subscriptionId | lc | IN($scope[])))
| ($planBy[.subscriptionId | lc] // {tier: "unknown", subPlan: ""}) as $plan
| ($mdeBy[.subscriptionId | lc].mde // (if $plan.tier == "Standard" then "unknown" else "n/a" end)) as $mde
| (if .kind == "VM" then exposure(.nicIds; $nicBy; $pipBy; $nsgBy; $subnetBy; $ports)
   else {publicIps: [], openPorts: []} end) as $x
| . + {subscription: ($subBy[.subscriptionId | lc].name // .subscriptionId),
       mgPath: ($subBy[.subscriptionId | lc].mgChain | mgpath),
       plan: (if $plan.tier == "Standard" then "Standard \($plan.subPlan // "")" else $plan.tier end),
       mde: $mde,
       edr: edr(.exts; $plan; $mde; $other),
       securityExtensions: ([.exts[] | "\(.publisher).\(.extType)" | select(lc | test("mde\\.|antimalware|" + $other))] | unique | join(", ")),
       publicIps: $x.publicIps, openPorts: $x.openPorts}
| . + {risk: risk}
| del(.exts, .nicIds)
JQ

jq -n -c \
  --slurpfile subs "$RAW/subs.jsonl" --slurpfile pricing "$RAW/pricing.jsonl" \
  --slurpfile pricingRest "$RAW/pricing_rest.jsonl" --slurpfile mdeSettings "$RAW/mde_settings.jsonl" \
  --slurpfile vms "$RAW/vms.jsonl" --slurpfile vmext "$RAW/vmext.jsonl" --slurpfile vmss "$RAW/vmss.jsonl" \
  --slurpfile arc "$RAW/arc.jsonl" --slurpfile arcext "$RAW/arcext.jsonl" \
  --slurpfile nics "$RAW/nics.jsonl" --slurpfile pips "$RAW/pips.jsonl" \
  --slurpfile nsgs "$RAW/nsgs.jsonl" --slurpfile subnets "$RAW/subnets.jsonl" \
  --argjson scope "$SUBS_JSON" --argjson ports "$PORTS_JSON" --arg other "$OTHER_EDR" \
  "$JQ_MODEL" > "$RAW/model.jsonl" || die "report building failed (raw data kept in $RAW)"

# ---------------------------------------------------------------- 4. reports
JQ_LABEL='def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];'

jq -r -s "$JQ_LABEL"'
  (["risk", "kind", "machine", "subscription", "subscriptionId", "resourceGroup", "location", "os", "osDetail",
    "state", "endpointProtection", "securityExtensions", "defenderPlan", "mdeIntegration", "publicIps",
    "mgmtPortsOpenToInternet", "aksNodePool", "managementGroups"] | @tsv),
  (sort_by(-.risk, .subscription, .name)[]
   | [(.risk | risklabel), .kind, .name, .subscription, .subscriptionId, .resourceGroup, .location, .osType,
      (.osDetail | gsub("^ +| +$"; "")), .state, .edr, .securityExtensions, .plan, .mde,
      (.publicIps | join(", ")), (.openPorts | map(tostring) | join(", ")), (if .aks then "yes" else "" end), .mgPath]
   | @tsv)' "$RAW/model.jsonl" > "$OUTDIR/machines.tsv"

jq -r -n --slurpfile m "$RAW/model.jsonl" --slurpfile subs "$RAW/subs.jsonl" \
  --slurpfile pricing "$RAW/pricing.jsonl" --slurpfile pricingRest "$RAW/pricing_rest.jsonl" \
  --slurpfile mdeSettings "$RAW/mde_settings.jsonl" --argjson scope "$SUBS_JSON" '
  def lc: ascii_downcase;
  def unprotected: startswith("NONE") or . == "AV ONLY" or test("failed");
  (($pricing + $pricingRest) | map({key: (.subscriptionId | lc), value: .}) | from_entries) as $planBy
  | ($mdeSettings | map({key: (.subscriptionId | lc), value: .mde}) | from_entries) as $mdeBy
  | ($m | group_by(.subscriptionId | lc) | map({key: (.[0].subscriptionId | lc), value: .}) | from_entries) as $mBy
  | (["subscription", "subscriptionId", "state", "defenderTier", "defenderSubPlan", "mdeIntegration",
      "machines", "activeMachines", "unprotected", "unprotectedActive", "internetMgmtPortsOpen", "critical",
      "managementGroups"] | @tsv),
    ($subs | sort_by(.name | lc)[]
     | select(($scope | length) == 0 or (.subscriptionId | lc | IN($scope[])))
     | (.subscriptionId | lc) as $k | ($mBy[$k] // []) as $ms | ($planBy[$k] // {}) as $p
     | [.name, .subscriptionId, .state, ($p.tier // "unknown"), ($p.subPlan // ""), ($mdeBy[$k] // ""),
        ($ms | length), ([$ms[] | select(.active)] | length),
        ([$ms[] | select(.edr | unprotected)] | length),
        ([$ms[] | select(.active and (.edr | unprotected))] | length),
        ([$ms[] | select(.openPorts | length > 0)] | length),
        ([$ms[] | select(.risk == 4)] | length),
        ([(.mgChain // [])[] | .displayName] | reverse | join(" / "))]
     | @tsv)' > "$OUTDIR/subscriptions.tsv"

log "Done. Machines by endpoint protection:"
jq -r -s 'group_by(.edr | sub(":.*"; "")) | sort_by(-length)[] | "  \(.[0].edr | sub(":.*"; "")): \(length)"' "$RAW/model.jsonl" >&2
log "Machines by risk:"
jq -r -s "$JQ_LABEL"'group_by(.risk) | reverse[] | "  \(.[0].risk | risklabel): \(length)"' "$RAW/model.jsonl" >&2
log "Reports in $OUTDIR (keep them private)."
