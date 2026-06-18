# JA4/JA4S threat-hunting workbook — user guide

This standalone guide helps you use a Microsoft Sentinel workbook (interactive investigation dashboard; see Glossary) that reads JA4 and JA4S (client and server TLS fingerprints; see Glossary) from Microsoft Defender `DeviceNetworkEvents` (network telemetry table; see Glossary), stays Microsoft E5-native (see Glossary), and uses no external threat-intelligence feeds (see Glossary) for its core detections; it serves Tier-1 security operations center analysts (SOC analysts; see Glossary) first and gives detection engineers (see Glossary) enough context to tune and promote hunts later.

🔴 Critical = act now > High > 🟠 Medium = review > 🔵 Low/Info

- [What and why](#what-and-why)
- [Prerequisites](#prerequisites)
- [Deploy](#deploy)
- [Quickstart — your first JA4 investigation](#quickstart-your-first-ja4-investigation)
- [Concepts — how JA4 and the scores work](#concepts-how-ja4-and-the-scores-work)
- [How-to guides](#how-to-guides)
- [Panel reference](#panel-reference)
- [Parameter reference](#parameter-reference)
- [Data requirements](#data-requirements)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)
- [Changelog and sources](#changelog-and-sources)

## What and why

## Prerequisites

Confirm this checklist before you deploy:

- [ ] ✅ `DeviceNetworkEvents` includes `ActionType == "SslConnectionInspected"` rows and JA4/JA4S values in `AdditionalFields` (dynamic field bag; see Glossary).
- [ ] ✅ `DeviceNetworkEvents` includes `ActionType == "ConnectionSuccess"` rows so the workbook can attribute network activity to processes (see Glossary).
- [ ] ✅ `SecurityIncident` and `SecurityAlert` (Microsoft Sentinel incident and alert tables; see Glossary) exist in the workspace for incident-match panels.
- [ ] ✅ Optional per-panel tables are available when you want those panels: `DeviceFileEvents` for file/download corroboration, `IdentityInfo` for identity context, and `EmailEvents` for phishing chains.
- [ ] ✅ Your account has at least workbook read access and Microsoft Sentinel read access through RBAC (role-based access control; see Glossary).

Sections with no matching data return **no rows** — that is not an error.

## Deploy

Use the Azure portal path for the fastest first deployment:

1. Open the **Deploy to Azure** or **Deploy to Azure US Gov** button in [README.md](README.md#deploy-the-workbook).
2. Choose the target resource group.
3. Set `workspaceResourceId` to the Log Analytics workspace (see Glossary) that backs Microsoft Sentinel.
4. Select **Review + create**.

Gov/IL5 note: use the US Gov button and Azure Government portal; the templates contain no cloud-specific endpoints.

For Bicep, Azure CLI, and Az PowerShell deployment paths, use [deploy/README.md](deploy/README.md) instead of copying commands from this guide.

## Quickstart — your first JA4 investigation

## Concepts — how JA4 and the scores work

## How-to guides

## Panel reference

## Parameter reference

## Data requirements

## Troubleshooting

## Glossary

## Changelog and sources
