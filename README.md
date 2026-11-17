# azure-edr-inventory

A read-only Bash script that shows **which servers in your Azure tenant have no endpoint protection
(EDR/AV)** and **which of them are open to the internet**. It covers virtual machines, scale sets and
Azure Arc machines across every subscription, and sorts them by a rough risk rating.

```bash
./azure-edr-inventory.sh          # whole tenant
```

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

## Safety

- **Read-only.** The script only uses `az graph query` and `az rest --method GET`. It changes nothing.
- **The output is sensitive.** It lists unprotected and internet-exposed servers with their public IPs,
  which is an attacker's shopping list. Files are created mode `600` (owner-only). Keep them private, and
  never commit them (the `.gitignore` in this repo excludes them).

## Requirements

- **Bash 4+** and **jq 1.6+**. Works on Linux, WSL, and macOS with Homebrew `bash`.
  [Azure Cloud Shell](https://shell.azure.com) has both.
- **Azure CLI**, signed in with `az login`, plus the Resource Graph extension:
  ```bash
  az extension add --name resource-graph
  ```
- **Permissions:** **Reader** on the tenant root management group (or on every management group and
  subscription you want covered). Reading the Defender settings may need **Security Reader** in some
  tenants.

## Usage

```bash
git clone https://github.com/JoeHun0/azure-edr-inventory.git
cd azure-edr-inventory
./azure-edr-inventory.sh                       # whole tenant
./azure-edr-inventory.sh -s <subId> -s <subId> # only these subscriptions
./azure-edr-inventory.sh -p "22 3389"          # management ports to check (default "22 3389 5985 5986")
./azure-edr-inventory.sh -S                    # skip the per-subscription Defender settings calls
./azure-edr-inventory.sh -o ~/reports/edr      # choose the output folder
./azure-edr-inventory.sh -h                    # help
```

Most of the data comes from a few paged Azure Resource Graph queries, so even large tenants finish in
minutes. The only per-subscription calls are for the Defender for Endpoint integration setting (only for
subscriptions with Defender for Servers on; `-S` skips them) and for the Defender plan of subscriptions
Resource Graph doesn't return. Run it from a folder outside any git repository.

## Output

Results go to `./edr-inventory-YYYYMMDD-HHMM/` (or the folder given with `-o`) as tab-separated files.
They open directly in LibreOffice Calc or Excel.

| File | Contents |
|---|---|
| `machines.tsv` | One row per machine, highest risk first: kind, name, subscription, resource group, location, OS, OS detail, state, endpoint protection, security extensions, Defender plan, MDE integration, public IPs, management ports open to the internet, AKS node pool, management groups |
| `subscriptions.tsv` | One row per subscription: Defender for Servers tier and sub-plan, MDE integration, number of machines, active machines, unprotected, unprotected and active, machines with management ports open to the internet, critical machines, management groups |
| `raw/` | The JSON lines the reports are built from, for your own queries with `jq` |

## Risk rating

A **heuristic to sort by**, not a verdict. *Unprotected* means `NONE…`, `AV ONLY` or a failed MDE
extension. *Active* means a running VM, a scale set with more than 0 instances, or a connected Arc machine
(a VM with unknown power state counts as active).

| Rating | Condition |
|---|---|
| **CRITICAL** | Unprotected, active, **and** management ports open to the internet |
| **HIGH** | Management ports open to the internet (even if protected), or unprotected and active (except AKS node pools) |
| **MEDIUM** | Unprotected but not active (deallocated, scaled to 0, disconnected), or an unprotected AKS node pool (AKS nodes are usually covered by Defender for Containers instead) |
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
  console.
- Defender for Servers set at **resource level** (per VM) instead of per subscription isn't read.
- Exposure is evaluated for VMs only. For scale sets and Arc machines (whose network is outside Azure),
  the exposure columns are empty.
- Azure public cloud only.

## After the inventory

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
