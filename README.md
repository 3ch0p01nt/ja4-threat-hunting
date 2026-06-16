# JA4 / JA4S Threat Hunting (Microsoft Sentinel)

[![validate](https://github.com/3ch0p01nt/ja4-threat-hunting/actions/workflows/validate.yml/badge.svg)](https://github.com/3ch0p01nt/ja4-threat-hunting/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Microsoft Sentinel workbook + KQL toolkit that stacks **JA4/JA4s TLS fingerprints**, fuses them with
incidents, scores **incident-match fidelity**, triages **rare suspicious fingerprints**, and detects
**beaconing** — all Microsoft Defender / E5-native (no external threat-intel feeds).

## Deploy the workbook

[![Deploy To Azure US Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2F3ch0p01nt%2Fja4-threat-hunting%2Fmain%2Fdeploy%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2F3ch0p01nt%2Fja4-threat-hunting%2Fmain%2Fdeploy%2FcreateUiDefinition.json)
&nbsp;
[![Deploy To Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2F3ch0p01nt%2Fja4-threat-hunting%2Fmain%2Fdeploy%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2F3ch0p01nt%2Fja4-threat-hunting%2Fmain%2Fdeploy%2FcreateUiDefinition.json)

Use the **US Gov** button for IL5 (Azure Government). On the deploy blade, pick your resource group and
set **`workspaceResourceId`** to your Log Analytics / Sentinel workspace, then **Review + create**.

> CLI / Bicep / Az PowerShell instructions: see [`deploy/README.md`](deploy/README.md).

## What's inside
| File | What it does |
|---|---|
| `07-ja4-threat-hunting-workbook.json` | The full interactive workbook (deployed by the buttons above). |
| `00-discovery-additionalfields-keys.kql` | Confirm the JA4 keys in `AdditionalFields`. |
| `01` / `03` | Signature-centric **incident-match fidelity** (Defender XDR / Sentinel). |
| `02` / `04` | Incident-centric per-pair fidelity. |
| `05-rare-ja4-malice-triage.kql` | Rare-fingerprint malice triage (structure / process / cert signals). |
| `06-ja4-beaconing.kql` | Low-jitter C2 beaconing detector. |
| `deploy/` | ARM + Bicep + parameters + Gov-aware deploy script. |

## Scoring (all data-driven, no embedded IOC lists)
- **Rarity** = combined: rare only if on *few hosts AND few connections*. A **Min rarity** slider focuses every panel on the rare tail.
- **Incident-match fidelity** = specificity (flow-exact > host+time > host-any > shared-IP) × temporal decay × rarity × **incident severity**.
- **Malice triage** = rarity-gated + corroboration-required (LOLBIN / legacy-TLS / self-signed-to-public / no-SNI / no-ALPN / user-path).
- **Beaconing** = low coefficient-of-variation on inter-arrival times.

## Data requirements
The target workspace needs Defender XDR data: `DeviceNetworkEvents` (`SslConnectionInspected` with JA4 in
`AdditionalFields`, plus `ConnectionSuccess` for process attribution) and `SecurityIncident` / `SecurityAlert`.
It deploys regardless — sections without data simply return no rows.

## Sources / methodology
MISP decaying models (temporal decay) · Pyramid of Pain (JA4 ranks above IP) · JA4 spec (structure decode) ·
detection-engineering proximity scoring · Recorded Future / STIX confidence bands.
