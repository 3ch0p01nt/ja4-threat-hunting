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
| `08-improvement-journey-workbook.json` | Companion **native workbook** telling the 10-cycle improvement story (datatable-driven line/bar charts + a cycle grid). |
| `00-discovery-additionalfields-keys.kql` | Confirm the JA4 keys in `AdditionalFields`. |
| `01` / `03` | Signature-centric **incident-match fidelity** (Defender XDR / Sentinel). |
| `02` / `04` | Incident-centric per-pair fidelity. |
| `05-rare-ja4-malice-triage.kql` | Rare-fingerprint malice triage (structure / process / cert signals). |
| `06-ja4-beaconing.kql` | Low-jitter C2 beaconing detector. |
| `08-first-seen-ja4.kql` | Brand-new JA4 in the estate (anti-join vs baseline) - new-implant signal. |
| `09-cipher-cycling-ja4ac.kql` | JA4_ac actor tracking - one a+c with many cipher variants (evasion). |
| `10-known-malware-pairs.kql` | **Opt-in** known-bad JA4+JA4S lookup + JA4X-approx self-CA cert structure (public FoxIO data). |
| `11-process-ja4-mismatch.kql` | Process vs JA4-library contradiction (b-section library ID) - uTLS parroting / injection / loaders. |
| `12-c2-tls-shape.kql` | Cobalt Strike / Meterpreter shape: TLS1.2 + no-ALPN + LOLBIN to non-MS dest, or exact CS c-section / JA4S. |
| `13`-`15` | **Endpoint corroboration**: Mark-of-the-Web->C2, detonation (rare JA4 + ASR/alert), suspicious process lineage. |
| `16`-`18` | **Identity & cloud**: AiTM (risky Entra sign-in + rare JA4), cloud exfil (unsanctioned-app upload), phish->implant chain. |
| `19`-`21` | **Inventory & hygiene**: deprecated-TLS compliance, structurally-impossible JA4, fleet cross-OS / JA4-proliferation. |
| `22`-`24` | **Destination anomalies**: LOTS/domain-fronting paradox, ECH/hidden-SNI, shadow-IT (non-browser SaaS access). |
| `25-process-ja4-baseline.kql` | Known-good (process -> TLS-library) catalog to learn the estate and tune allowlists. |
| `deploy/` | ARM + Bicep + parameters + Gov-aware deploy script. |

## Scoring (core signals are data-driven; known-bad lookup is opt-in)
- **Rarity** = combined: rare only if on *few hosts AND few connections*. A **Min rarity** selector focuses every panel on the rare tail.
- **Incident-match fidelity** = specificity (flow-exact > host+time > host-any > shared-IP) × temporal decay × rarity × **incident severity**.
- **Malice triage** = rarity-gated + corroboration-required. Strong: LOLBIN / legacy-TLS / self-signed-to-public / no-TLS-extensions. Weak (need 2): no-SNI / no-ALPN / user-path / SNI=IP / abnormal cipher count. A self-CA cert (issuer has no `O=`) approximates a JA4X C2 cert; an **age discount** demotes aged, widespread fingerprints. Verdict tops out at **Critical**.
- **Beaconing** = low coefficient-of-variation on inter-arrival times.
- **First-seen / cipher-cycling** = brand-new JA4 in the estate; one JA4_ac with many cipher variants.
- **Known-bad (opt-in)** = exact JA4+JA4S match against FoxIO's public ja4plus-mapping (embedded static table, not a premium feed), plus a JA4X-approximation on self-CA cert structure. Toggle **Known-bad lookup = On** in the workbook to enable.
- **C2 tradecraft** = the JA4 b-section (chars 11-22, sorted-cipher hash) is a stable TLS-**library** identifier; a contradiction with the attributed process (browser library from a non-browser, Python/Go from a LOLBIN, any TLS from a script-host LOLBIN) catches uTLS parroting / injection / loaders. A TLS1.2 + no-ALPN + LOLBIN shape (or the exact Cobalt Strike c-section / server JA4S) catches CS / Meterpreter.
- **FP suppression** = known-good library+process pairs and Microsoft-issued certs are down-weighted; Microsoft destinations are excluded from the tradecraft detectors.

## Performance
Every query uses a `has "ja4"` term-index prefilter before `todynamic()`, a single-pass rarity computation,
and an **early rarity gate** so the expensive joins (process attribution, incident correlation, beaconing)
run only over the rare tail. Beaconing uses `make_list` + `mv-apply` (no global `serialize`). The workbook
loads **one section at a time** (conditionally-visible groups don't run their queries), so the whole
dashboard never scans `DeviceNetworkEvents` for every panel at once. The large per-connection base is
deliberately **not** `materialize()`d (that exceeds Kusto's 5 GB cache at production scale); only small
per-pair / entity results are materialized.

## Data requirements
The target workspace needs Defender XDR data: `DeviceNetworkEvents` (`SslConnectionInspected` with JA4 in
`AdditionalFields`, plus `ConnectionSuccess` for process attribution) and `SecurityIncident` / `SecurityAlert`.
It deploys regardless — sections without data simply return no rows.

## Sources / methodology
MISP decaying models (temporal decay) · Pyramid of Pain (JA4 ranks above IP) · JA4 / JA4+ spec (structure
decode, JA4_ac) · FoxIO ja4plus-mapping (opt-in known-bad only) · detection-engineering proximity scoring ·
Recorded Future / STIX confidence bands.

