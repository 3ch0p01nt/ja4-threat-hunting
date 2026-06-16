# JA4 / JA4S Threat-Hunting Workbook — code deployment

Infrastructure-as-Code to deploy the **JA4/JA4S Threat Hunting** Microsoft Sentinel workbook
into any Log Analytics / Sentinel workspace. **Cloud-agnostic** — works in Azure Commercial
and **Azure Government (IL5)** (`usgovvirginia`, `usgovarizona`, DoD regions).

## Contents
| File | Purpose |
|---|---|
| `main.bicep` | **Recommended.** Bicep that loads the workbook via `loadTextContent()`. |
| `workbook-content.json` | The workbook definition (serialized). Edited by Bicep/ARM at deploy. |
| `azuredeploy.json` | ARM template (workbook embedded) — for ARM-only pipelines / portal. |
| `azuredeploy.parameters.json` | Fill in your workspace ID + region. |
| `Deploy-Ja4Workbook.ps1` | Gov-aware az-CLI helper (sets cloud, parses sub/RG, deploys). |

## Prerequisites
- **RBAC:** `Contributor` (or `Microsoft.Insights/workbooks/write`) on the target resource group.
- **Tooling:** Azure CLI (`az`) or Az PowerShell, with the **Azure Government** cloud selected.
- **Data:** the workbook queries these tables in the target workspace — they must be present
  (Defender XDR data streamed to Sentinel):
  - `DeviceNetworkEvents` with `ActionType == "SslConnectionInspected"` and JA4/JA4s in
    `AdditionalFields` (Corelight/Zeek-style TLS inspection), plus `ActionType == "ConnectionSuccess"`
    (for process attribution).
  - `SecurityIncident`, `SecurityAlert` (incident-match fidelity).
  If a table is missing the workbook still deploys; those sections simply return no rows.

## Deploy

Get your workspace resource ID first:
```powershell
az cloud set --name AzureUSGovernment
az login
az monitor log-analytics workspace show -g <workspace-rg> -n <workspace-name> --query id -o tsv
```

### Option A — Bicep (recommended)
```powershell
az deployment group create -g <workspace-rg> --template-file main.bicep `
  --parameters workspaceResourceId="<workspace-resource-id>" location="usgovvirginia"
```

### Option B — ARM template
```powershell
az deployment group create -g <workspace-rg> --template-file azuredeploy.json `
  --parameters "@azuredeploy.parameters.json"
```

### Option C — helper script (handles cloud + sub/RG automatically)
```powershell
.\Deploy-Ja4Workbook.ps1 -WorkspaceResourceId "<workspace-resource-id>" -Login
# preview without changing anything:
.\Deploy-Ja4Workbook.ps1 -WorkspaceResourceId "<workspace-resource-id>" -WhatIf
```

### Option D — Az PowerShell
```powershell
Connect-AzAccount -Environment AzureUSGovernment
Set-AzContext -Subscription <sub-id>
New-AzResourceGroupDeployment -ResourceGroupName <workspace-rg> -TemplateFile .\azuredeploy.json `
  -workspaceResourceId "<workspace-resource-id>" -location usgovvirginia
```

## After deploying
Open **Microsoft Sentinel → your workspace → Workbooks → My workbooks → “JA4/JA4S Threat Hunting”**
(portal is `https://portal.azure.us` for Government).

Two controls at the top:
- **Lookback** — time window (default 30 days).
- **Min rarity** — focus on rare fingerprints; rare = *few hosts AND few connections*
  (`All / Uncommon 0.5 / Rare 0.7 / Very rare 0.85 / Singletons 0.95`, default **Rare**).

Sections: summary tiles · **Top Prioritized Leads** (what + why) · suspicious-fingerprint triage ·
incident-match fidelity · beaconing call-homes · rarity landscape.

## Idempotency & updates
The workbook name is a **deterministic GUID** (`guid(resourceGroup().id, displayName)`), so
re-running the deployment **updates the same workbook in place**. To ship a new version of the
queries, replace `workbook-content.json` and redeploy.

## Notes for Azure Government / IL5
- The templates contain **no cloud-specific endpoints** — they deploy through whatever ARM
  endpoint your CLI/PowerShell context targets, so selecting `AzureUSGovernment` is all that’s needed.
- `category: "sentinel"` + `sourceId` (your workspace) make it appear under Sentinel’s Workbooks gallery.
- No external threat-intel feeds or internet calls — all logic is self-contained KQL against your workspace.
