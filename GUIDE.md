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

Use this linear walkthrough for your first 10-minute hunt. For control definitions, use [Parameter reference](#parameter-reference); for score meanings, use [Concepts — how JA4 and the scores work](#concepts-how-ja4-and-the-scores-work).

1. Open Microsoft Sentinel, choose your workspace, and open the **JA4/JA4S Threat Hunting** workbook.
2. Set **Lookback window** (time range control; see Glossary) to **7d**.
3. Set **Min rarity** (rarity gate; see Glossary) to **0.7**.
4. Set **Section** (workbook view selector; see Glossary) to **Top Leads**.
5. Set **Known-bad lookup** (static known-malware comparison; see Glossary) to **Off**.
6. Read the first red row. Start with **Verdict**, then **Score**, then **Why**.
7. Copy the `ja4_` value from that row.
8. Use the row's **Procs** value and destination (remote service; see Glossary) to pivot into the device timeline in Microsoft Defender.
9. Match the process, destination, and row verdict against this decision tree:

```text
Top red row
  |
  +-- Critical or High, Score >= 50, and Procs is unknown or unexpected?
  |       -> Escalate and attach the ja4_ value, process, destination, and row details.
  |
  +-- Medium, Score >= 30, and Procs is expected for the destination?
  |       -> Review the device timeline and document benign context.
  |
  +-- Low/Info or known business process?
          -> Close as informational unless another panel corroborates it.
```

You've completed your first hunt — next: [Worked example A](#worked-example-a-rare-ja4-process-mismatch).

## Concepts — how JA4 and the scores work

This section explains the fields and scores you read in the workbook. Use it when a row has a score you need to interpret before you escalate or close.

### JA4 structure

JA4 splits the TLS ClientHello (client setup message; see Glossary) into an a-section (clear-text feature string; see Glossary), b-section (cipher-suite hash; see Glossary), and c-section (extension and signature-algorithm hash; see Glossary). This diagram uses zero-based character positions.

```text
t13d1516h2_8daaf6152771_e5627efa2ab1
|--------| |----------| |----------|
 0    9    11      22   24      35
 a-section b-section  c-section

 a-section chars 0-9:  t | 13 | d | 15 | 16 | h2
                        |   |   |    |    |   |
                        |   |   |    |    |   +-- ALPN (application-layer protocol negotiation; see Glossary)
                        |   |   |    |    +------ extension count
                        |   |   |    +----------- cipher count
                        |   |   +---------------- SNI flag (server name indication; see Glossary)
                        |   +-------------------- TLS version
                        +------------------------ protocol family

 b-section chars 11-22: 8daaf6152771 = sorted-cipher hash = a version-stable TLS library identifier
 c-section chars 24-35: e5627efa2ab1 = extension+sigalg hash = extension and signature-algorithm shape
```

The a-section tells you the visible ClientHello shape: protocol, TLS version, SNI flag, cipher count, extension count, and ALPN. Normal browsers and platform libraries usually produce stable a-sections for a given release family.

The b-section is the stable library clue. When a non-browser process presents a Chromium-like or Firefox-like b-section, you should treat the process and library combination as a contradiction until the device timeline explains it.

The c-section captures extension ordering and signature algorithms. It often stays consistent for a toolchain even when the destination changes.

### JA4S, JA4_ac, and why this beats JA3 and IP

JA4S (server TLS fingerprint; see Glossary) describes the ServerHello (server setup response; see Glossary). JA4 plus JA4S lets you compare both sides of a TLS session instead of judging only the client.

JA4_ac (a+c composite fingerprint; see Glossary) keeps the a-section and c-section while dropping the b-section. That makes it stable across cipher rotation (cipher cycling; see Glossary). Use it when a tool rotates cipher suites but keeps the same broader client shape.

JA4 beats JA3 (older TLS fingerprint format; see Glossary) and IP address indicators (network locations; see Glossary) because it sits higher on the Pyramid of Pain (defender model for indicator durability; see Glossary). Attackers can change IPs quickly, but changing a TLS library or malware TLS stack without breaking behavior costs more effort.

### SslConnectionInspected is metadata, not decryption

`SslConnectionInspected` records ClientHello and ServerHello metadata inspection. It is **not** TLS decryption: the workbook can see fingerprint shape, timing, destination, certificate metadata, and process context, but it cannot read page content, message bodies, credentials, or decrypted files.

### Rarity

Formula: `R = min(Rhost, Rconn)`, where each component is `log(N/n) / log(N)`.

| Rarity value | Meaning |
|---|---|
| `≥ 0.95` | ≈ ~1 device or near-singleton activity. |
| `0.85–0.95` | Very few devices or connections. |
| `0.7–0.85` | Uncommon and inside the default hunt focus. |
| `< 0.7` | Common or likely benign. |

Worked example: in a fleet with `N ≈ 332,000` devices, a fingerprint seen on `n = 3` devices has `Rhost = log(332000/3) / log(332000) ≈ 0.91`. If it appears in `n = 50` connections, `Rconn = log(332000/50) / log(332000) ≈ 0.69`, so `R = min(0.91, 0.69) = 0.69`.

Normal vs suspicious: normal browser and update traffic often lands below `0.7`; suspicious rows combine high rarity with an unexpected process, unknown destination, or another corroborating panel.

### MatchFidelity

Formula: `MatchFidelity = 100 × Specificity × TemporalDecay × Rarity × SeverityWeight`.

- Specificity (match closeness; see Glossary): flow-exact `1.0` > host+time `0.85` > host-any `0.6` > shared-IP `0.35`.
- TemporalDecay (time-distance discount; see Glossary): `max(0.02, 1 − (dt/τ)²)`, with `τ = 2h`.
- SeverityWeight (incident severity multiplier; see Glossary): High `1.0`, Medium `0.7`, Low `0.45`, Informational or unknown `0.2`.
- Bands: High `>= 75`, Medium `>= 40`, Low `>= 20`, Informational `> 0`.

Worked example: a flow-exact match to a High incident, `30m` from the alert, with `Rarity = 0.85` scores `100 × 1.0 × (1 − (0.5h/2h)²) × 0.85 × 1.0 = 79.7`, which rounds to High.

Normal vs suspicious: normal rows are loose shared-IP or old host-any matches with common fingerprints; suspicious rows are recent, flow-exact or host+time matches on rare fingerprints tied to High or Medium incidents.

### SuspicionScore

Formula: `SuspicionScore = clamp(0, 100, strong adders + supporting adders − benign penalties)`.

Strong adders: LOLBIN (living-off-the-land binary; see Glossary) `+35`, self-signed-to-public certificate `+30`, legacy-TLS `+25`, and no-extensions `+20`. Benign penalties: known-good library+process `−30`, Microsoft-issued certificate `−20`, and aged+widespread `−15`.

Bands: Critical `>= 80`, High `>= 50`, Medium `>= 30`, Low `< 30`.

Worked example: `rundll32.exe` to a public destination with a self-signed certificate, legacy TLS, and no extensions scores `35 + 30 + 25 + 20 = 110`, then clamps to `100`, so the verdict is Critical.

Normal vs suspicious: normal rows lose urgency when the TLS library matches the expected process, the certificate is Microsoft-issued, or the fingerprint is aged and widespread; suspicious rows keep multiple strong adders after those penalties.

### BeaconScore

Base formula: `CVScore = 100 × (1 − CV)`, where `CV = stddev / mean` for inter-arrival times. Current formula: `BeaconScore = max(CVScore, IQRScore)`, where `IQRScore` is an interquartile-range score (IQR; see Glossary) that tolerates occasional jitter.

Pattern = regular / jittered / low-and-slow. Regular means the cadence is tight, jittered means the cadence has deliberate or natural variation, and low-and-slow means few connections spread over a long span still keep a regular cadence.

Worked example: call-home gaps of `10, 10, 11, 9, 10, 35` minutes have an outlier. Mean is about `14.2`, sample standard deviation is about `10.2`, `CV ≈ 0.72`, and `CVScore ≈ 28`. The IQR score stays near `90` because most gaps remain `9-11` minutes, so the BeaconScore stays high and the Pattern is jittered.

Normal vs suspicious: normal software update checks may be regular but usually use common JA4 values and trusted destinations; suspicious beacons pair high BeaconScore with rare JA4, unknown destinations, raw IPs, no SNI, or an unexpected process.

### Verdict legend recap

🔴 Critical = act now > High > 🟠 Medium = review > 🔵 Low/Info.

## How-to guides

### Worked example A — rare JA4 process mismatch

## Panel reference

## Parameter reference

## Data requirements

## Troubleshooting

## Glossary

## Changelog and sources
