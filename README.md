# azure-edr-inventory

A read-only Bash script that shows **which servers in your Azure tenant have no endpoint protection
(EDR/AV)** and **which of them are open to the internet**. It covers virtual machines, scale sets and
Azure Arc machines across every subscription, and sorts them by a rough risk rating.

```bash
./azure-edr-inventory.sh          # whole tenant
```

## Quick start

1. Sign in with the Azure CLI and add the Resource Graph extension (once):
   ```bash
   az login
   az extension add --name resource-graph
   ```
2. Run the inventory. It only reads. Expect a few minutes, even for large tenants:
   ```bash
   ./azure-edr-inventory.sh        # add -r if a schedule starts and stops your VMs
   ```
   The results go to a new folder, `./edr-inventory-YYYYMMDD-HHMM/`.
3. Turn the results into a report and a worklist:
   ```bash
   ./edr-summary.sh edr-inventory-YYYYMMDD-HHMM
   ```
4. Use the two files it writes into the folder:
   - **`edr-report.md`**: counts only, with no names. Paste it into your report or ticket.
   - **`edr-worklist.csv`**: one row per thing to fix, with severity, what to do and the details. Load it into
     Excel (*Data → From Text/CSV*) and assign rows to the people who fix them.

   Everything else in the folder (the `.tsv` files and `raw/`) is the detailed inventory. Keep it private.

On Windows, run the scripts in **Git Bash** or **WSL** with the Azure CLI installed. Run them from a folder
outside any git repository, so the results can't be committed by accident.

## Why

A server without EDR is a blind spot. Nothing stops malware or ransomware on it, and the security team
gets no process, network or logon telemetry, so it can't see what an attacker does there. In large Azure
estates, protection is often switched on per subscription, deployed per VM, or depends on someone
remembering an agent. Gaps pile up unseen: subscriptions without Microsoft Defender for Servers,
Linux VMs where the agent never installed, scale sets built from an old image, Arc servers that dropped
off.

The worst case is a server with **no EDR and RDP/SSH open to the internet**. This script finds those
first.

## What it reports

For every **VM, VM scale set and Azure Arc machine** in every subscription:

| | |
|---|---|
| **Machine** | kind, OS and OS version (or image), power state / scale set capacity / Arc connection status, AKS node pool flag, management group path |
| **Endpoint protection** | Microsoft Defender for Endpoint (`MDE.Windows` / `MDE.Linux` extension, including failed installs), other EDR vendors deployed as extensions (CrowdStrike, SentinelOne, Trend Micro, Sophos, …), or Microsoft Antimalware only |
| **Subscription plan** | Microsoft Defender for Servers tier (Free / Plan 1 / Plan 2) and whether its Defender for Endpoint integration (`WDATP` setting) is on |
| **Internet exposure** (VMs) | public IPs, and which management ports (default 22, 3389, 5985, 5986) the NIC and subnet NSGs leave open to the internet |
| **AKS** | for every AKS cluster: whether the subscription has the Microsoft Defender for Containers plan on and the cluster runs the Defender sensor. A scale set counts as an AKS node pool only when it sits in a cluster's node resource group (or carries AKS's node-pool tag, see orphans below); it then gets its cluster's status. Other scale sets are judged like VMs |

The `endpointProtection` column can show:

| Value | Meaning |
|---|---|
| `MDE` | Defender for Endpoint extension installed (check sensor health in the Defender portal) |
| `MDE - extension failed` | Extension present but failed to provision: treated as unprotected |
| `OTHER EDR: <extension>` | Another vendor's agent deployed as a VM extension: check that it reports to your SOC |
| `AV ONLY` | Only Microsoft Antimalware (`IaaSAntimalware`): antivirus, not EDR |
| `NONE - Defender plan on, no sensor` | Defender for Servers is on, but no sensor was deployed (unsupported OS, VM off during rollout, provisioning error) |
| `NONE - Defender plan on, MDE integration off` | The plan is paid for, but the Defender for Endpoint integration is switched off, so nothing gets deployed |
| `NONE` | No plan and no agent |
| `DEFENDER FOR CONTAINERS` | AKS node pool whose cluster is covered: Containers plan on and sensor deployed (AKS nodes are protected by Defender for Containers, not Defender for Servers) |
| `NONE - Containers plan on, no sensor` | AKS node pool: the plan is on, but the Defender sensor isn't deployed to the cluster |
| `NONE - no Defender for Containers` | AKS node pool: the subscription doesn't have the Defender for Containers plan |
| `NONE - orphaned AKS node pool` | Scale set that carries AKS's node-pool tag, but no AKS cluster uses its resource group any more: left behind after the cluster was deleted |

## Safety

- **Read-only.** The script only uses `az graph query` and `az rest --method GET`. It changes nothing.
- **The output is sensitive.** It lists unprotected and internet-exposed servers with their public IPs,
  which is an attacker's shopping list. Files are created mode `600` (owner-only). Keep them private, and
  never commit them (the `.gitignore` in this repo excludes them).

## Requirements

- **Bash 4+** and **jq 1.6+**. Works on Linux, WSL, macOS with Homebrew `bash`, and Git Bash on Windows (the script handles the CRLF line endings of the Windows `az` and `jq`, and Git Bash's path rewriting).
  [Azure Cloud Shell](https://shell.azure.com) has both.
- **Azure CLI**, signed in with `az login`, plus the Resource Graph extension:
  ```bash
  az extension add --name resource-graph
  ```
- **Permissions:** **Reader** on the tenant root management group (or on every management group and
  subscription you want covered). Reading the Defender settings may need **Security Reader** in some
  tenants.
  If the account can't read the tenant root management group, for example because a **PIM role isn't active**,
  the script warns at the start and the summary report says the inventory is incomplete. Activate the role
  and run `az login` again before you start.

## Usage

```bash
git clone https://github.com/JoeHun0/azure-edr-inventory.git
cd azure-edr-inventory
./azure-edr-inventory.sh                       # whole tenant
./azure-edr-inventory.sh -s <subId> -s <subId> # only these subscriptions
./azure-edr-inventory.sh -p "22 3389"          # management ports to check (default "22 3389 5985 5986")
./azure-edr-inventory.sh -S                    # skip the per-subscription Defender settings calls
./azure-edr-inventory.sh -r                    # VMs on a start/stop schedule: rate stopped VMs as running
./azure-edr-inventory.sh -R edr-inventory-20261117-0930   # rebuild ratings and reports from raw/ (no Azure calls)
./azure-edr-inventory.sh -o ~/reports/edr      # choose the output folder
./azure-edr-inventory.sh -h                    # help
```

Most of the data comes from a few paged Azure Resource Graph queries, so even large tenants finish in
minutes. The only per-subscription calls are for the Defender for Endpoint integration setting (only for
subscriptions with Defender for Servers on; `-S` skips them) and for the Defender plan of subscriptions
Resource Graph doesn't return. Run it from a folder outside any git repository.

**Rebuild (`-R`).** Re-runs only the rating and report steps on the `raw/` data of an earlier run. It makes
no Azure calls and takes seconds. Use it after updating the script, or to re-rate with `-r`, other ports
(`-p`) or a subscription filter (`-s`). Then run `edr-summary.sh` again.

## Output

Results go to `./edr-inventory-YYYYMMDD-HHMM/` (or the folder given with `-o`) as tab-separated files.
They open directly in LibreOffice Calc or Excel.

| File | Contents |
|---|---|
| `machines.tsv` | One row per machine, highest risk first: kind, name, subscription, resource group, location, OS, OS detail, state, endpoint protection, security extensions, Defender plan, MDE integration, public IPs, management ports open to the internet, AKS node pool, management groups, AKS cluster |
| `subscriptions.tsv` | One row per subscription: Defender for Servers tier and sub-plan, MDE integration, number of machines, active machines, unprotected, unprotected and active, machines with management ports open to the internet, critical machines, management groups, Defender for Containers tier, AKS clusters, AKS clusters not covered |
| `aks_clusters.tsv` | One row per AKS cluster, uncovered first: subscription, resource group, location, Kubernetes version, power state, Defender for Containers plan, automatic sensor provisioning in the plan, sensor on the cluster, status, number of node pools, management groups, node resource group |
| `raw/` | The JSON lines the reports are built from, for your own queries with `jq` |

For a shareable summary and a to-do list, run `edr-summary.sh` on the folder: see [Report and worklist](#report-and-worklist).

## Risk rating

A **heuristic to sort by**, not a verdict. *Unprotected* means `NONE…`, `AV ONLY` or a failed MDE
extension. *Active* means a running VM, a scale set with more than 0 instances, or a connected Arc machine
(a VM with unknown power state counts as active).

**VMs on a start/stop schedule:** if an automation starts and stops your VMs, a VM that happens to be off
during the run is still in daily use. Run the inventory with `-r` (or during working hours), so stopped VMs
and scale sets at 0 instances are rated as if they were running. The `state` column still shows the real
state.

| Rating | Condition |
|---|---|
| **CRITICAL** | Unprotected, active, **and** management ports open to the internet |
| **HIGH** | Management ports open to the internet (even if protected), or unprotected and active (an AKS node pool counts as protected when its cluster is covered by Defender for Containers) |
| **MEDIUM** | Unprotected but not active (deallocated, scaled to 0, disconnected) |
| **LOW** | Protected, not exposed |

### How internet exposure is evaluated

For each VM network interface with a public IP, a management port counts as open when **every** NSG in
the path (the NIC's NSG and the subnet's NSG) allows it. An NSG allows it when its **first matching inbound
rule by priority** has source `*`, `Internet`, `Any`, `0.0.0.0/0` or `::/0`, protocol TCP or `*`, and a
destination port, range or list that covers the port, and that rule's action is *Allow*. With **no NSG at
all**, a *Basic* public IP is treated as open and a *Standard* one as closed (Standard IPs block inbound
traffic by default).

This is a static approximation of Azure's effective security rules. It does **not** consider Azure
Firewall or NVAs, load balancer inbound NAT rules, application security groups, service tags other than
`Internet`, or destination address filters. Use *Effective security rules* on the NIC in the portal, or
Network Watcher, to confirm a finding.

## Limitations

- **Agents installed inside the OS without a VM extension are invisible** to the Azure control plane: an
  EDR installed by GPO, Intune, Ansible or an image appears as `NONE`. Check these against your EDR
  console. Defender for Endpoint onboarded by script also appears as `NONE`, but shows up in the Defender
  portal.
- An installed extension doesn't prove a **healthy, reporting** sensor. Check sensor health in your EDR
  console. For AKS the same goes for the Defender sensor: "on" in the cluster's settings doesn't prove
  that the sensor pods run.
- Defender for Servers set at **resource level** (per VM) instead of per subscription isn't read.
- Exposure is evaluated for VMs only. For scale sets and Arc machines (whose network is outside Azure),
  the exposure columns are empty.
- Azure public cloud only.

## Report and worklist

`edr-summary.sh` turns an output folder into two files. It needs only `jq`, no Azure access:

```bash
./edr-summary.sh edr-inventory-20261117-0930             # writes both files into that folder
./edr-summary.sh -s ';' edr-inventory-20261117-0930      # ";" as CSV separator
./edr-summary.sh -o ~/reports edr-inventory-20261117-0930   # writes them somewhere else
```

| File | Contents | Share? |
|---|---|---|
| `edr-report.md` | Counts only: coverage, protection status by OS, internet exposure, Defender for Servers plans, a fix-first list | Yes. No names, IDs or IP addresses, so it can go into a report or ticket |
| `edr-worklist.csv` | One row per thing to fix, with severity, priority (1 = most urgent), category, issue, the action to take, and the details needed to do it: machine, subscription and its ID, resource group, location, OS, state, protection status, Defender plan, MDE integration, public IPs, open management ports, AKS node pool, management groups, resource ID | Internal only. Share single rows with the people who fix them |

Worklist categories: `EDR-CRITICAL` (unprotected, running, ports open to the internet), `EDR-EXPOSED`, `EDR-MISSING`, `EDR-MISSING-INACTIVE`, `EDR-AKS-ORPHAN` (node pool left behind by a deleted cluster), `EDR-OTHER-VERIFY` (another vendor's agent: confirm it reports to the SOC), per AKS cluster `AKS-NO-CONTAINERS` and `AKS-SENSOR-OFF`, and per subscription `SUB-NO-DEFENDER` and `SUB-MDE-OFF`.

Notes on the CSV:
- **`item_id` (category:resource ID or subscription ID) stays the same between runs.** Use it as the key in a tracking spreadsheet: load the CSV with *Data → From Text/CSV* (Power Query), keep columns like assignee, status and due date in a separate table joined on `item_id`, and refresh after the next run. Fixed items drop out of the CSV.
- **Encoding:** UTF-8 with a byte-order mark, so Excel shows accented characters correctly. Values that start with `=`, `+`, `-` or `@` get a leading `'`, so names can't run as Excel formulas.
- **Separator:** `,` by default. Excel with a Hungarian or German locale expects `;` when you open the file by double-clicking, so use `-s ';'` for that.

## After the inventory

The worklist (`edr-worklist.csv`, see [Report and worklist](#report-and-worklist)) contains these steps as one row per machine or subscription and issue, ready to assign.

These are common next steps, roughly in order:

1. **CRITICAL first:** close the management ports (use Azure Bastion or just-in-time VM access instead
   of open RDP/SSH), then deploy an EDR and check the machines for signs of compromise.
2. Enable **Defender for Servers** (or your EDR) through **Azure Policy at management-group level**, so
   every current and future subscription is covered. Check that the Defender for Endpoint integration is
   switched on.
3. Fix `NONE - Defender plan on, no sensor` and `MDE - extension failed` machines one by one. They're
   usually an unsupported OS or kernel, or a VM that was off during rollout.
4. Build the agent into VM images and infrastructure-as-code modules, and alert on machines that lose
   their sensor.

## Tests

```bash
tests/run-tests.sh
```

The tests run the script against a mock `az` (`tests/mock/az`) that simulates a small tenant: protected,
unprotected and exposed VMs, NSG priority and port-range cases, Basic and Standard public IPs, scale sets,
AKS node pools, Arc machines, Resource Graph paging and the REST fallback. They need only `bash` and `jq`,
not Azure access. They also run on every push through GitHub Actions.

## License

[MIT](LICENSE)
