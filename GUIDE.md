# JA4/JA4S threat-hunting workbook — user guide

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

This standalone guide helps you use a Microsoft Sentinel workbook (interactive investigation dashboard; see Glossary) that reads JA4 and JA4S (client and server TLS fingerprints; see Glossary) from Microsoft Defender `DeviceNetworkEvents` (network telemetry table; see Glossary), stays Microsoft E5-native (see Glossary), and uses no external threat-intelligence feeds (see Glossary) for its core detections; it serves Tier-1 security operations center analysts (SOC analysts; see Glossary) first and gives detection engineers (see Glossary) enough context to tune and promote hunts later.

🔴 Critical = act now > High > 🟠 Medium = review > 🔵 Low/Info

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

You've completed your first hunt — next: [Worked example A](#worked-example-a-cobalt-strike-shape).

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

Use these procedures when you need to turn a workbook row into a decision. Start with the Tier-1 steps; use the detection-engineer callout only when you own tuning or rule creation.

### Investigate a rare TLS fingerprint

1. Start from a **Top Leads** or [Suspicious rare JA4 triage](#03-suspicious-rare-ja4-triage-hunt-wb_triagekql) row with an uncommon `ja4_`. Read **Verdict**, **Score**, **Why**, **Rarity**, **Procs**, **Dests**, **FirstSeen**, and **LastSeen**.
2. Confirm the process. If **Procs** is empty or surprising, pivot from **DeviceName** or **DeviceId** plus the row time window into the Microsoft Defender device timeline and look for the matching connection.
3. Confirm the destination. Treat public, non-Microsoft, raw-IP, no-SNI, or newly seen destinations as more suspicious than known business services.
4. Decode the fingerprint enough to explain the signal: the a-section gives the visible TLS shape, the b-section suggests the TLS library, and the c-section can identify a stable toolchain shape.
5. Review the device timeline for process tree, command line, signer, folder path, file downloads, logons, and nearby alerts.
6. Escalate when rarity plus process/destination evidence stays suspicious. Dismiss only when the process, signer, folder, destination, and timeline all explain the row as expected business activity. Record the `ja4_`, `ja4s_`, process, destination, time window, and reason.

### Detect C2 beaconing from a host

1. Set **Section** to **Hunt** and open the [Beaconing call-homes](#04-beaconing-call-homes-hunt-wb_beaconkql) panel.
2. Start with rows that combine high **BeaconScore**, high **Rarity**, and an unfamiliar **Dest** or **SampleRemoteIP**.
3. Read **DeviceName**, `ja4_`, **Dest**, **BeaconScore**, **Connections**, **MedianIntervalMin**, **JitterCV**, **Rarity**, **SpanHours**, **FirstSeen**, and **LastSeen**.
4. Pivot to the device timeline for the same device and time window. Identify the process that made the repeated connections and check its signer, path, command line, parent process, and recent file activity.
5. Compare the destination with known update, telemetry, and security-agent services. Benign software can beacon; suspicious C2 usually pairs regular timing with a rare JA4, a public non-corporate destination, no SNI, or an unexpected process.
6. Escalate when the same host shows regular call-homes plus a rare fingerprint and unexplained process or destination. Close as benign only when the process and destination are approved and the timeline has no corroborating suspicious activity.

### Enable and use the known-bad lookup

1. Set **Known-bad lookup** to **On** before you run the [Known-malware JA4+JA4S lookup](#08-known-malware-ja4ja4s-lookup-known-bad-reference-wb_malwarekql) view.
2. Use this lookup deliberately: it runs the opt-in FoxIO public known-malware JA4 mapping embedded as a static table in the workbook, not a live premium feed.
3. Read **Verdict**, **Family**, **MatchType**, `ja4_`, `ja4s_`, **Devices**, **DeviceNames**, **Conns**, **Dests**, **Issuers**, **FirstSeen**, and **LastSeen**.
4. Treat an exact **JA4+JA4S pair** hit as critical after you verify it occurred on the listed device and destination. The embedded pair table includes Sliver, IcedID, Cobalt Strike, and SoftEther VPN fingerprints; the single-JA4 table includes SoftEther VPN IP-SNI and Evilginx AiTM shapes.
5. Verify the row before acting. Fingerprints rotate, some tools can be sanctioned in limited environments, and single-JA4 matches such as Evilginx need identity or session-theft corroboration.
6. Escalate verified malware-pair hits with the family, `ja4_`, `ja4s_`, device, destination, and time window. For Evilginx, pivot to sign-in logs before you decide the account action.

### Tune false positives with the process→JA4 baseline

1. Set **Section** to **Destination & inventory** and open the [Process-to-JA4 baseline](#07-process-to-ja4-baseline-destination-inventory-wb_baselinekql) panel.
2. Use the baseline as your local known-good catalog. It lists expected **Proc**, **Library**, **bsec**, **DistinctDevices**, **TotalConns**, **DistinctJA4s**, **Signers**, **SampleSNIs**, **FirstSeen**, and **LastSeen**.
3. For a noisy mismatch row, compare its process and b-section with the baseline. A common, signed, fleet-wide `(process, library)` pair with expected sample SNIs is a stronger false-positive candidate than a one-off user-path process.
4. Add allowlist entries as narrowly as possible: process name plus b-section/library, signer, and destination class when available. Avoid allowlisting an entire JA4 if only one approved application explains it.
5. Re-run the mismatch and Top Leads panels. The tuned entry should suppress only the expected `(process, library)` pair and should not hide user/temp paths, LOLBINs, or non-Microsoft external destinations.
6. Document the allowlist reason, owner, evidence, and review date so a future analyst knows why the row disappeared.

### Adjust beacon thresholds

1. Start from the default beacon controls: **Beacon min connections** = `8` and **Beacon min score** = `50`.
2. Lower **Beacon min connections** to `4` or **Beacon min score** to `40` when you are hunting low-and-slow malware or a short incident window. Expect more benign updater and telemetry rows.
3. Raise **Beacon min connections** to `12` or `16`, or **Beacon min score** to `60` or `70`, when the panel is noisy and you need only the most regular call-home patterns.
4. Re-run the panel after each change and compare row count, **BeaconScore**, **Connections**, **Rarity**, **Dest**, and **DeviceName**.
5. Keep the threshold set that still surfaces the suspicious host while removing explained business traffic. Save the setting for the hunt notes or propose it for an analytic rule only after validation.

### 🔧 For detection engineers: promote a panel to a Sentinel analytic rule

1. Choose a panel that already produces a clear Tier-1 action, such as known-bad pair hits, C2 TLS shape, process/library mismatch, or AiTM corroboration.
2. Copy the panel KQL into a scheduled Microsoft Sentinel analytic rule and keep the workbook comment header so future maintainers know the hypothesis and source panel.
3. Set **Rule name** to the analyst task and signal, for example `JA4 - Cobalt Strike TLS shape`.
4. Set **Severity** to match the panel verdict you want to alert on: Critical for exact malware fingerprints, High for corroborated C2 or AiTM patterns, and Medium for review-only hunts.
5. Set **MITRE tactic/technique** to the behavior the panel detects, such as Command and Control for beaconing or Credential Access/Initial Access for AiTM session theft.
6. Set **Run frequency** and **Lookback** so the lookback is at least as long as the frequency and wide enough for the panel logic. Beaconing and AiTM windows usually need more lookback than exact known-bad matches.
7. Set **Alert threshold** to `> 0` results unless you deliberately aggregate multiple rows before alerting.
8. Set **Entity mapping** from the columns the panel returns: host from **DeviceName** or **DeviceId**, IP from **RemoteIP**, **SampleRemoteIP**, or **SignInIP**, account from **UPN**, URL/DNS from **Dest** or **SNI**, and keep `ja4_`, `ja4s_`, process, verdict, and why fields as custom details.
9. Run the query over recent data, confirm the alert payload includes enough context for triage, then enable the rule.

### Worked example A — Cobalt Strike shape

**Situation:** A Top Leads or [C2 TLS-shape / Cobalt Strike](#02-c2-tls-shape-cobalt-strike-hunt-wb_c2shapekql) row reports client `t12i190700_d83cc789557e_16bbda4055b2` with server JA4S `t120300_c030_52d195ce1d92`.

**Decode the signal:** The client JA4 starts with TLS 1.2 and no ALPN, and its c-section is `16bbda4055b2`. The FoxIO JA4 mapping embedded in the toolkit identifies that c-section as the Cobalt Strike WinINET beacon client section. The server JA4S `t120300_c030_52d195ce1d92` is the matching Cobalt Strike server fingerprint.

**Corroborate:** Check **Why** for `CS client c-section` and `CS server JA4S`. Then check **Procs**, **Dests**, **Devices**, **Conns**, **AnyUserPath**, **FirstSeen**, and **LastSeen**. In the confirmed case, **Procs** is `rundll32.exe` and **Dests** is a non-Microsoft external destination.

**Verdict:** Cobalt Strike is confirmed. The two exact tells are the client c-section `16bbda4055b2` and the server JA4S `t120300_c030_52d195ce1d92`; `rundll32.exe` to a non-Microsoft external destination corroborates execution.

**Action:** Escalate to incident response, isolate the device, attach the row details, and hunt the same `ja4_` fleet-wide.

### Worked example B — AiTM session theft

**Situation:** The AiTM corroboration panel shows a risky Entra sign-in and a rare or non-browser JA4 on that user's device within 30 minutes. The JA4 is the Evilginx shape `t13d191000_9dc949149365_e7c285222651`.

**Decode the signal:** The panel treats `t13d191000_9dc949149365_e7c285222651` as an Evilginx AiTM JA4. Its b-section `9dc949149365` overlaps with Go tooling, so you should not rely on the JA4 alone; the risky sign-in and time proximity are the decisive corroboration.

**Corroborate:** Check **UPN**, **DeviceName**, **RiskLevel**, **RiskState**, `ja4_`, `ja4s_`, **bsec**, **Rarity**, **nonBrowser**, **SignInIP**, **Location**, **AppDisplayName**, **SNI**, **SignInTime**, **ConnTime**, **TimeGapMin**, and **Why**. A small **TimeGapMin** and a target app such as O365 or SharePoint point to business-email-compromise risk.

**Verdict:** Treat the row as critical AiTM session theft when the Evilginx JA4, risky sign-in, and 30-minute device correlation all line up.

**Action:** Revoke the user's sessions, force MFA re-registration, preserve SigninLogs and device/network evidence, and hand the case to the identity or IR owner.

### Worked example C — process/library mismatch

**Situation:** The [Process -> JA4 library mismatch](#01-process---ja4-library-mismatch-hunt-wb_mismatchkql) panel reports b-section `8daaf6152771` attributed to `rundll32.exe`.

**Decode the signal:** The b-section `8daaf6152771` is the Chromium TLS library. `rundll32.exe` is a LOLBIN and should not originate Chromium-style TLS. That contradiction points to uTLS parroting, DLL injection, or a loader borrowing another TLS stack. Because `rundll32.exe` is a LOLBIN, the panel's **Mismatch** column shows the LOLBIN reason first; a non-LOLBIN non-browser process, such as a random user-path binary, is the cleaner illustration of the pure Chromium-library mismatch case.

**Corroborate:** Check **Severity**, **Mismatch**, **Proc**, **bsec**, `ja4_`, **Devices**, **Conns**, **AnyUserPath**, **ProcFolders**, **Dests**, **FirstSeen**, and **LastSeen**. A non-Microsoft external destination makes the row malicious until proven otherwise; a Microsoft domain can be a benign WebView2 false positive that needs timeline review.

**Verdict:** Treat `rundll32.exe` plus Chromium b-section `8daaf6152771` to a non-Microsoft external destination as a high-severity process/library mismatch consistent with injection or TLS parroting.

**Action:** Investigate the process tree in the Microsoft Defender device timeline, then isolate and escalate if the parent process, command line, folder path, or destination remains unexplained.

## Panel reference

This reference explains what each workbook panel shows, how to read its highest-value columns, and when to escalate or tune the result.

> **Note on the Tunables lines below.** Each entry lists the panel's own `let lookback = 30d;` as written in its query. In the deployed workbook the **Lookback window** parameter (default **7d** — see [Parameter reference](#parameter-reference)) overrides this for every panel, so the window you actually see is set by the dropdown at the top, not the hardcoded `30d`.

### 01 Top Prioritized Leads   (leads · `wb_leads.kql`)
**What it detects:** The highest-priority JA4/JA4S leads across three engines: suspicious rare fingerprints, beaconing call-homes, and fingerprints that correlate to existing Sentinel incidents.
**Hunt hypothesis:** "Malware command-and-control or hands-on-keyboard tooling shows up as rare TLS client/server fingerprints, periodic TLS call-homes, or TLS fingerprints near an existing incident in Defender XDR and Sentinel telemetry."
**MITRE ATT&CK:** T1071.001 (Application layer protocol: Web protocols) · T1573 (Encrypted channel)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `TimeGenerated`, `DeviceId`, `DeviceName`, `RemoteIP`, `RemotePort`, `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `AdditionalFields.issuer`, `AdditionalFields.subject`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`; `SecurityIncident` and `SecurityAlert` — `IncidentNumber`, `Title`, `Severity`, `AlertIds`, `SystemAlertId`, entity `MdatpDeviceId`, entity `Address`; rarity-gated: yes for the suspicious-fingerprint and beacon engines, while the incident engine also keeps the inline known-bad JA4/JA4S seed pairs; known-bad lookup: n/a (not the opt-in workbook lookup).
**How it works:** The query computes combined rarity `R = min(host rarity, connection rarity)` for each JA4/JA4S pair, then filters the high-volume network stream to rare pairs with an efficient small-set broadcast filter. Engine 1 scores rare public-destination fingerprints with corroborating process/certificate/JA4-structure signals; engine 2 finds regular rare JA4 call-homes; engine 3 correlates rare or inline known-bad pairs to `SecurityIncident`/`SecurityAlert` within tight time/entity windows. The top 50 rows are sorted by `Score` and `LastSeen`; use the Sources & validation card for the FoxIO JA4 mapping, LOLBAS LOLBIN definitions, MITRE ATT&CK C2 context, and Pyramid of Pain rationale.

**Sample query (excerpt):** the detection heart of `wb_leads.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | lookup kind=leftouter (rare | project ja4_, ja4s_, R) on ja4_, ja4s_
    | extend MatchFidelity = toint(round(100.0 * rowScore * coalesce(R, 1.0)))
    | where MatchFidelity >= 40
    | extend MatchTier = case(Stier == 1.0, "flow-exact", Stier == 0.85, "host+time", Stier == 0.6, "host-any", "shared-ip")
    | project Category = "Matches an incident", Score = MatchFidelity, JA4 = strcat(ja4_, "  /  ", ja4s_), Why = strcat(MatchTier, " match to incident #", IncidentNumber, " (", ITitle, "), ", toint(dt / 60), " min from alert"), Where = ITitle, Detail = strcat("incident #", IncidentNumber), LastSeen = cT;
union triage, beacon, fidelity
| extend NextStep = case(
    Category == "Suspicious fingerprint", "Verify the process is one you expect on this host; check the destination; review the device timeline. Unknown process + self-signed cert to a public IP = isolate + escalate.",
    Category == "Beaconing call-home", "Judge the destination (known vendor/update vs raw IP / unknown domain); confirm the interval looks C2-like; then check DNS and the calling process.",
    Category == "Matches an incident", "Open the linked incident - this fingerprint is added evidence. Sweep other hosts for the same JA4.",
    "Read the Why, then confirm the process and destination.")
| project Score, Category, Why, Destination = Where, Hosts = Detail, NextStep, JA4, LastSeen
| sort by Score desc, LastSeen desc
| take 50
```

**Output columns** — | Column | What it means |
|---|---|
| `Score` | A 0-100 priority score, but the formula depends on `Category`: suspicious fingerprints use the additive TLS/process `SuspicionScore`; beaconing uses regularity score; incident matches use severity-, time-, specificity-, and rarity-weighted `MatchFidelity`. Higher means investigate first within that category. |
| `Category` | Which engine produced the row: `Suspicious fingerprint`, `Beaconing call-home`, or `Matches an incident`. Read this before interpreting `Score` because each category scores differently. |
| `Why` | Plain-English evidence. It already states the observable, what that observable means, and why it is suspicious, such as "LOLBIN process (system binary that should not originate TLS)" or "self-signed cert to a public host (legit public services present a CA-issued cert)." |
| `Destination` | For suspicious fingerprints, up to three sample SNI host names; for beaconing, the SNI destination or `RemoteIP` fallback; for incident matches, the incident title. Empty or IP-only destinations deserve extra scrutiny. |
| `Hosts` | Context for scope. For suspicious fingerprints this is the number of hosts, for beaconing this is one sample device name, and for incident matches this is `incident number`. |
| `NextStep` | The query-authored Tier-1 instruction for that row. It tells you which pivot to take next: process/destination check, beacon validation, or opening the linked incident and sweeping for the JA4. |
| `JA4` | The fingerprint key. Suspicious and incident rows show `JA4 / JA4S` (client TLS fingerprint plus server TLS fingerprint); beacon rows show the client `JA4` only. JA4 identifies the client TLS handshake shape; JA4S identifies the server TLS response shape. |
| `LastSeen` | Most recent matching TLS event time for the row. Recent rows are more actionable than old rows with the same score. |

**Reading this output:** Start with the highest `Score`, then read `Category`, then read `Why`. The `Why` column is already self-explanatory evidence: it tells you the observable, translates the jargon, and explains why it matters, so do not re-decode the JA4 before understanding the row. A normal row usually has a known business destination, expected process, or a linked benign incident; a suspicious row combines rarity with a risky public destination, a LOLBIN or user-path process, a self-signed certificate, periodic timing, or a close incident match.

**Verdict / severity bands** — | Value | Threshold | Means | Action |
|---|---:|---|---|
| `Suspicious fingerprint` row | `Score >= 30` after adders and penalties | The JA4/JA4S pair is rare and has either at least one strong signal or at least two weak signals. | Follow `NextStep`: validate process and destination; isolate/escalate if an unknown process uses a self-signed certificate to a public IP. |
| `Beaconing call-home` row | `Conns >= 8`, mean interval `30..172800` seconds, and `Score >= 70` | The rare JA4 calls the same destination at a low-jitter interval. | Check whether the destination is a vendor/update service or an unknown domain/raw IP, then pivot to DNS and process telemetry. |
| `Matches an incident` row | `MatchFidelity >= 40` | The JA4/JA4S is close to a Sentinel incident by host/IP/time and weighted by incident severity. | Open the incident, treat the fingerprint as corroborating evidence, and sweep other hosts for the same JA4. |
| `Top 50` display limit | `take 50` after sorting by `Score desc, LastSeen desc` | Only the strongest current leads are shown. | If you need broader hunting, lower thresholds or use the underlying specialist panels. |

**Tunables:** `lookback = 30d` controls history and cost; `minRarity = 0.7` raises or lowers the rare-pair gate; suspicious fingerprint adders are fixed (`LOLBIN +35`, `self-signed public +30`, `legacy TLS +25`, `no TLS extensions +20`, weaker adders `+8..+15`, Microsoft issuer `-20`, aged+widespread `-15`); beacon sub-engine requires `Conns >= 8`, interval `30 seconds..2 days`, and `BScore >= 70`; incident sub-engine uses exact flow within `15 minutes`, host+time within `2 hours`, or weaker host/shared-IP matches.
**False positives:** Benign rare enterprise software or new rollout → rarity gate plus Microsoft-issuer and aged-widespread score discounts → confirm the process path, publisher, change ticket, and destination ownership. Benign updaters/AV/browser telemetry → beacon score and destination grouping suppress irregular traffic, but no vendor allowlist is applied → check whether the destination is a known vendor service. Existing incident noise → severity/time/entity weighting suppresses weak matches → open the incident and verify the JA4 is relevant to the alert entities.
**Example row:** `Score=82, Category=Suspicious fingerprint, Why="LOLBIN process (system binary that should not originate TLS); self-signed cert to a public host (legit public services present a CA-issued cert)", Destination="198.51.100.20", Hosts="1 host(s)", JA4="t13i190800_9dc949149365_97f8aa674fd9 / t130200_1301_a56c5b993250"` → high-priority lead because a rare client/server TLS shape is tied to a Windows system binary and a public self-signed certificate.
**Next step:** Do exactly what `NextStep` says for the category. Escalate to Tier-2/IR when the process is unknown or LOLBIN-driven, the destination is an unknown domain/raw public IP, the certificate is self-signed public, or the same JA4 appears on multiple hosts.

### 02 Summary KPI tiles   (leads · `wb_tiles.kql`)
**What it detects:** This landing panel does not detect a single threat; it summarizes JA4 telemetry volume, rarity focus, and obvious TLS risk signals for the current lookback.
**Hunt hypothesis:** "A hunt is ready to run when JA4 telemetry is present, rare-pair counts are small enough to triage, and risk tiles such as public self-signed or public no-SNI pairs are visible."
**MITRE ATT&CK:** N/A (coverage and orientation panel; it supports C2 hunts rather than detecting one adversary behavior)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `TimeGenerated`, `DeviceId`, `RemoteIP`, `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `AdditionalFields.issuer`, `AdditionalFields.subject`; rarity-gated: no, although several tiles count pairs where `R >= minRarity`; known-bad lookup: n/a.
**How it works:** The query counts devices, distinct JA4 client fingerprints, distinct JA4/JA4S pairs, destinations, and legacy TLS connections across the lookback. It also calculates combined rarity for each JA4/JA4S pair and uses `minRarity = 0.7` to count rare-focus pairs, rare public self-signed pairs, and rare public no-SNI pairs. Use Microsoft Learn from the Sources & validation card for Defender table and field meanings, and the Pyramid of Pain card to explain why fingerprint counts matter more than IP counts.

**Sample query (excerpt):** the detection heart of `wb_tiles.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let scored = pairs
    | extend R = min_of(iff(totalDevices <= 1, 1.0, max_of(0.0, log(todouble(totalDevices) / todouble(Devs)) / log(todouble(totalDevices)))),
                        iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns)))));
union
 (baseMetrics | project Value = Devices     | extend Metric = "Devices seen", Sort = 1),
 (baseMetrics | project Value = DistinctJA4 | extend Metric = "Distinct client fingerprints", Sort = 2),
 (scored | summarize Value = count() | extend Metric = "JA4 x JA4S pairs (all)", Sort = 3),
 (scored | where R >= minRarity | summarize Value = count() | extend Metric = "Rare pairs (focus)", Sort = 4),
 (scored | where R >= minRarity and AnySelf == 1 | summarize Value = count() | extend Metric = "Rare + self-signed (public)", Sort = 5),
 (scored | where R >= minRarity and AnyNoSNIpub == 1 | summarize Value = count() | extend Metric = "Rare + no-SNI (public)", Sort = 6),
 (baseMetrics | project Value = LegacyConns   | extend Metric = "Legacy-TLS connections", Sort = 7),
 (baseMetrics | project Value = DistinctDests | extend Metric = "Distinct destinations", Sort = 8)
| project Metric, Value, Sort
| sort by Sort asc
```

**Output columns** — | Column | What it means |
|---|---|
| `Metric` | The tile name. It tells you what the `Value` is counting. |
| `Value` | The numeric count for that metric in the `lookback` window. A value of `0` can mean a clean estate, missing telemetry, or a threshold that is too tight; compare it to the metric definition below. |
| `Sort` | A hidden/display-order helper from `1` to `8`. It is not a security signal; ignore it during triage. |

**Reading this output:** Read `Metric` and `Value` together; the panel has no `Why` or `Reasons` column because the tile label is the explanation. The possible metrics are: `Devices seen` = distinct Defender device IDs with JA4/JA4S TLS metadata; `Distinct client fingerprints` = distinct JA4 values; `JA4 x JA4S pairs (all)` = distinct client/server fingerprint pairs; `Rare pairs (focus)` = pairs with combined rarity `R >= 0.7`; `Rare + self-signed (public)` = rare pairs where the certificate issuer equals the subject and the destination IP is public; `Rare + no-SNI (public)` = rare pairs where the JA4 says no Server Name Indication was sent to a public IP; `Legacy-TLS connections` = connection count where the JA4 version segment indicates TLS older than 1.2 or SSL-like legacy negotiation; `Distinct destinations` = distinct SNI names. Normal estates often have large all-pair counts but much smaller rare-focus counts; suspicious hunts start when rare public self-signed, rare public no-SNI, or legacy-TLS values are non-zero and unexplained.
**Tunables:** `lookback = 30d` widens or narrows all counts; `minRarity = 0.7` controls only the three rare-focused tiles, where higher values reduce counts and lower values increase counts.
**False positives:** Inventory growth, browser updates, or new software rollouts → no alerting suppression is needed because this is an aggregate dashboard → compare against change windows and baseline panels before treating a tile as an incident. Missing JA4 onboarding → tile values may be zero or unexpectedly low → verify `SslConnectionInspected` events include `AdditionalFields.ja4`.
**Example row:** `Metric="Rare + self-signed (public)", Value=3, Sort=5` → review because three rare JA4/JA4S pairs used self-signed certificates to public IPs; that is not automatically malicious, but it is a small set suitable for Tier-1 triage.
**Next step:** If the rare-risk tiles are non-zero, open Top prioritized leads or Suspicious rare JA4 triage. If all tiles are zero, first validate telemetry before concluding the environment is clean.

### 03 Suspicious rare JA4 triage   (hunt · `wb_triage.kql`)
**What it detects:** Rare public-destination JA4/JA4S pairs that also have corroborating suspicious TLS structure, certificate, or process-attribution evidence.
**Hunt hypothesis:** "Malware or adversary tooling shows up as a rare TLS client/server fingerprint plus at least one strong suspicious signal or multiple weak suspicious signals in Defender network telemetry."
**MITRE ATT&CK:** T1071.001 (Application layer protocol: Web protocols) · T1218 (System binary proxy execution)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `TimeGenerated`, `DeviceId`, `RemoteIP`, `RemotePort`, `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `AdditionalFields.issuer`, `AdditionalFields.subject`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`; rarity-gated: yes (`R >= minRarity`); known-bad lookup: n/a.
**How it works:** The query first computes rarity for each JA4/JA4S pair and keeps only rare pairs, then joins those exact rare flows to `ConnectionSuccess` events within plus/minus `180` seconds to recover the initiating process. It requires corroboration: at least one strong signal (`LOLBIN`, legacy TLS, public self-signed certificate, or no TLS extensions to a public host) or at least two weak signals (no SNI, no ALPN, user/temp-path process, SNI is an IP, very few ciphers, or unusually many ciphers). It then scores the row from `0` to `100`, subtracts benign-rollout or known-good-library penalties, and uses the Sources & validation card for JA4 structure, LOLBAS, and Pyramid of Pain context.

**Sample query (excerpt):** the detection heart of `wb_triage.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| where StrongCount >= 1 or WeakCount >= 2              // CORROBORATION
| extend DaysActive = datetime_diff('day', LastSeen, FirstSeen)
| extend AgePenalty = iff(DaysActive > 14 and DistinctDevices >= 3, -15, 0)   // benign-rollout discount
| extend bsec = substring(ja4_, 11, 12), ProcsSafe = coalesce(Procs, dynamic([]))
| extend knownGoodLib = (
       (bsec in ("8daaf6152771", "55b375c5d22e") and array_length(set_intersect(ProcsSafe, dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe","arc.exe","msedgewebview2.exe","teams.exe","ms-teams.exe","slack.exe","code.exe","discord.exe"]))) > 0)
    or (bsec == "5b57614c22b0" and array_length(set_intersect(ProcsSafe, dynamic(["firefox.exe","thunderbird.exe","tor.exe","librewolf.exe"]))) > 0)
    or (bsec == "85036bcba153" and array_length(set_intersect(ProcsSafe, dynamic(["python.exe","python3.exe","pythonw.exe"]))) > 0))
| extend BenignPenalty = iff(knownGoodLib, -30, 0) + iff(AnyMsIssuer, -20, 0)
| extend SuspicionScore = max_of(0, min_of(100,
        iff(AnyLolbin, 35, 0) + iff(legacy, 25, 0) + iff(AnySelfSignedPub, 30, 0) + iff(noExt, 20, 0) + iff(AnyEmptyOrgPub, 10, 0)
      + iff(AnySniIpPub, 15, 0) + iff(fewCiphers, 12, 0) + iff(noSNI, 12, 0) + iff(AnyUserPath, 12, 0) + iff(manyCiphers, 10, 0) + iff(noALPN, 8, 0))
      + AgePenalty + BenignPenalty)
// …
| extend Verdict = case(SuspicionScore >= 80, "Critical", SuspicionScore >= 50, "High", SuspicionScore >= 30, "Medium", "Low")
| project ja4_, ja4s_, Verdict, SuspicionScore, Reasons, Procs, SampleSNIs, Issuers,
          Rarity = round(R, 2), DistinctDevices, DistinctRemoteIPs, TotalConnections, DaysActive, FirstSeen, LastSeen
| sort by SuspicionScore desc, Rarity desc, DistinctDevices asc
```

**Output columns** — | Column | What it means |
|---|---|
| `ja4_` | The JA4 client TLS fingerprint. It describes the client handshake shape, including TLS version, SNI behavior, cipher count/hash, extension count/hash, and ALPN hints. |
| `ja4s_` | The JA4S server TLS fingerprint paired with the client JA4. It describes the server response shape. A rare `ja4_` plus `ja4s_` pair is more specific than either side alone. |
| `Verdict` | Severity label derived only from `SuspicionScore`: `Critical`, `High`, `Medium`, or `Low`. It is the fastest triage indicator. |
| `SuspicionScore` | A 0-100 score. Adders include `LOLBIN +35`, public self-signed certificate `+30`, legacy TLS `+25`, no extensions `+20`, public SNI-is-IP `+15`, few ciphers/no SNI/user-path process `+12`, many ciphers `+10`, no ALPN `+8`, and empty certificate organization `+10`; penalties include known-good library+process `-30`, Microsoft issuer `-20`, and aged+widespread `-15`. |
| `Reasons` | Plain-English evidence list. Each item states the observable, what it is, and why it is suspicious; for example, "cert issuer has no Organization field (self-CA, mirrors Sliver/Havoc/Qakbot C2 certs)." Discount reasons are also included when a penalty was applied. |
| `Procs` | Up to eight initiating process names correlated to the rare TLS flows. LOLBINs and processes from user/temp paths are riskier than signed, expected application binaries. |
| `SampleSNIs` | Up to five Server Name Indication names seen for the pair. SNI is the hostname the client requested during TLS; empty, raw-IP, or unknown domains are more suspicious. |
| `Issuers` | Up to three certificate issuer strings. Self-signed public certificates, empty organization fields, or unexpected issuers increase suspicion. Microsoft/DigiCert Cloud Services issuers are discounted. |
| `Rarity` | Combined rarity rounded to two decimals: `R = min(host rarity, connection rarity)`. Values near `1.00` are seen on very few hosts and in very few connections; `0.70` is the panel's default minimum. |
| `DistinctDevices` | Number of distinct Defender devices that used this JA4/JA4S pair. One device can be a single infection; multiple devices can indicate spread or a legitimate rollout. |
| `DistinctRemoteIPs` | Number of distinct destination IPs for the pair. More destinations can indicate infrastructure rotation, but can also be normal cloud/CDN behavior. |
| `TotalConnections` | Total number of inspected TLS connections for the pair during `lookback`. A small count with high rarity is easier to triage; a large count may indicate common software despite rarity gating. |
| `DaysActive` | Number of days between `FirstSeen` and `LastSeen`. If `DaysActive > 14` and `DistinctDevices >= 3`, the query subtracts `15` points as an aged/widespread benign-rollout discount. |
| `FirstSeen` | Earliest matching TLS event in the lookback window. Use this to line up with installs, alerts, or user activity. |
| `LastSeen` | Latest matching TLS event in the lookback window. Recent activity is more urgent. |

**Reading this output:** Start with `Verdict`, then `SuspicionScore`, then `Reasons`. The `Reasons` column already explains the evidence in plain language, so a Tier-1 analyst should read it before trying to decode the JA4 string manually. Normal rows are usually explained by expected processes, known-good library/process pairs, Microsoft-issued certificates, or aged enterprise rollouts; suspicious rows have high rarity plus public self-signed certs, LOLBINs, no SNI/ALPN, raw-IP destinations, very small cipher sets, or user-path processes.

**Verdict / severity bands** — | Value | Threshold | Means | Action |
|---|---:|---|---|
| `Critical` | `SuspicionScore >= 80` | Multiple high-confidence signals or a very strong combination after penalties. | Escalate immediately if process/destination are not known-good; consider containment for active unknown public C2. |
| `High` | `SuspicionScore >= 50` and `< 80` | Strong suspicious signal or several weaker signals on a rare pair. | Triage now: validate process, certificate, SNI, and host timeline. |
| `Medium` | `SuspicionScore >= 30` and `< 50` | Enough corroboration to review, but less urgent or partially discounted. | Review during hunt queue; escalate if the process or destination is unexplained. |
| `Low` | `< 30` | Corroboration passed but score was reduced or weak. | Usually monitor or suppress after confirming a benign rollout. |
| Row eligibility | `R >= 0.7` and (`StrongCount >= 1` or `WeakCount >= 2`) | Common fingerprints and single weak hints are removed before scoring. | If you need broader hunting, lower `minRarity` or inspect the raw KQL logic. |

**Tunables:** `lookback = 30d` controls historical window; `minRarity = 0.7` tightens/loosens rare-pair eligibility; process attribution window is fixed at `±180 seconds`; strong/weak signal lists and score adders are fixed in the KQL; known-good browser/Firefox/Python library+process combinations apply a `-30` discount; Microsoft/DigiCert Cloud Services issuer applies `-20`; aged+widespread applies `-15`.
**False positives:** Internal appliances/printers and localhost services → certificate and structural signals only count for public destinations → verify `RemoteIP` ownership and whether SNI/destination is internal. Browser, Teams, Slack, VS Code, Firefox, or Python TLS libraries → known-good b-section library+process pairs are discounted → confirm process signer/path and user activity. Microsoft cloud services → Microsoft/DigiCert Cloud Services issuer is discounted → verify the destination is a legitimate Microsoft service. Enterprise rollouts → aged+widespread discount applies after more than `14` days on `3+` devices → check change records and software inventory.
**Example row:** `ja4_=t13i190800_9dc949149365_97f8aa674fd9, ja4s_=t130200_1301_a56c5b993250, Verdict=Critical, SuspicionScore=87, Reasons=["LOLBIN process (system binary that should not originate TLS)", "no SNI sent to a public host (evasive / automation client)", "self-signed cert to a public host (legit public services present a CA-issued cert)"], Procs=["rundll32.exe"], Rarity=0.96, DistinctDevices=1` → critical because a very rare public TLS pair is tied to a Windows LOLBIN, no SNI, and a public self-signed certificate.
**Next step:** Open the device timeline around `FirstSeen`/`LastSeen`, validate `Procs`, inspect destination ownership from `SampleSNIs`/remote IP, and escalate when the process is unknown/LOLBIN, the destination is public and unexplained, or the same rare pair appears on more than one host.

### 04 Beaconing call-homes   (hunt · `wb_beacon.kql`)
**What it detects:** Rare JA4 client fingerprints that call the same destination at a regular, jittered, or low-and-slow TLS cadence consistent with command-and-control beaconing.
**Hunt hypothesis:** "C2 implants show up as repeated TLS call-homes from one device to one SNI or IP destination with a stable JA4 and a measurable interval pattern."
**MITRE ATT&CK:** T1071.001 (Application layer protocol: Web protocols) · T1573 (Encrypted channel)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `TimeGenerated`, `DeviceId`, `DeviceName`, `RemoteIP`, `AdditionalFields.ja4`, `AdditionalFields.server_name`; rarity-gated: yes (`JA4 Rarity >= minRarity`); known-bad lookup: n/a.
**How it works:** The query groups events by `DeviceId`, `ja4_`, and destination, where destination is SNI when present and `RemoteIP` when SNI is empty. It calculates inter-arrival deltas, keeps median intervals from `30` seconds to `172800` seconds (`2` days), and computes a jitter-tolerant `BeaconScore` as the maximum of a coefficient-of-variation score and an interquartile-range score. Rows qualify either as normal beacon candidates (`Connections >= 8` and `BeaconScore >= 50`) or low-and-slow sleepers (`Connections >= 4`, `SpanHours >= 48`, and `BeaconScore >= 60`).

**Sample query (excerpt):** the detection heart of `wb_beacon.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
ssl
| where ja4_ in (rareJa4Set)   // broadcast-filter the firehose by the small rare-ja4 set (no shuffle)
| summarize Timestamps = make_list(TimeGenerated), Connections = count(), SampleRemoteIP = take_any(RemoteIP),
            DeviceName = take_any(DeviceName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by DeviceId, ja4_, Dest
// …
| extend CVScore = 100.0 * (1.0 - min_of(1.0, CV))
| extend RobustScore = iff(P75 == 0, 0.0, 100.0 * (todouble(P25) / todouble(P75)))   // IQR-based regularity: tolerates jitter + the few outliers that wreck a pure CV
| extend BeaconScore = toint(round(max_of(CVScore, RobustScore)))                     // best of tight-CV and robust-IQR, so a jittered-but-periodic beacon is not lost
| extend SpanHours = round(datetime_diff('minute', LastSeen, FirstSeen) / 60.0, 1)
| extend Pattern = case(Connections < minConns, "low-and-slow (sleeper)", CV > 0.25, "jittered", "regular")
| where (Connections >= minConns and BeaconScore >= minBeaconScore)
     or (Connections >= minConnsLow and SpanHours >= 48 and BeaconScore >= 60)        // low-and-slow: few call-homes over a long span, still regular = sleeper implant
| join kind=leftouter rarity on ja4_
| project DeviceName, ja4_, Dest, SampleRemoteIP, BeaconScore, Pattern, Connections,
          MedianIntervalMin = round(MedianSec / 60.0, 1), JitterCV = round(CV, 2),
          Rarity = round(Rarity, 2), SpanHours, FirstSeen, LastSeen
| sort by BeaconScore desc, Rarity desc, Connections desc
```

**Output columns** — | Column | What it means |
|---|---|
| `DeviceName` | Sample host name for the device that produced the beacon pattern. Use it to pivot to the device timeline. |
| `ja4_` | The JA4 client TLS fingerprint. A stable JA4 across repeated calls suggests the same TLS client/tool is making the call-homes. |
| `Dest` | Destination key: SNI hostname if the client sent one, otherwise the raw `RemoteIP`. Raw IP destinations or unknown domains are more suspicious than known vendor services. |
| `SampleRemoteIP` | One observed destination IP behind `Dest`. Useful for enrichment, but do not rely on it alone because cloud services rotate IPs. |
| `BeaconScore` | 0-100 regularity score. The code calculates `CVScore = 100 * (1 - min(1, CV))`, `RobustScore = 100 * P25/P75`, then uses `round(max(CVScore, RobustScore))`; this preserves jittered-but-periodic beacons that a pure CV score might miss. |
| `Pattern` | Human-readable cadence class: `regular`, `jittered`, or `low-and-slow (sleeper)`. `regular` means `CV <= 0.25`; `jittered` means `CV > 0.25` but the robust score still passed; `low-and-slow` means fewer than `8` connections over a long span still looked periodic. |
| `Connections` | Number of TLS events in the group. Standard candidates need at least `8`; low-and-slow candidates need at least `4` plus a long span. |
| `MedianIntervalMin` | Median time between calls, in minutes. This is the median, not the mean, so one delayed or extra call has less effect on the displayed interval. |
| `JitterCV` | Coefficient of variation, rounded to two decimals: standard deviation divided by mean interval. `0.00` is perfectly regular; higher values are more jittered. A row can still score well if the IQR-based robust score is strong. |
| `Rarity` | Combined rarity for the JA4 rounded to two decimals. Values near `1.00` mean few devices and few connections use this JA4; the panel keeps only `Rarity >= 0.70`. |
| `SpanHours` | Hours between the first and last observed call, rounded to one decimal. Low-and-slow rows require at least `48` hours. |
| `FirstSeen` | First call in the grouped pattern. Use it to identify when the behavior started. |
| `LastSeen` | Last call in the grouped pattern. Recent call-homes are more urgent. |

**Reading this output:** Start with `BeaconScore`, then `Pattern`, then `Dest`, then `MedianIntervalMin`. This panel does not emit a `Why` or `Reasons` column; instead, `Pattern`, `BeaconScore`, `MedianIntervalMin`, `JitterCV`, and `Rarity` are the evidence fields. Normal values usually point to known update, telemetry, AV, or browser destinations; suspicious values combine a high score, rare JA4, unknown or raw-IP destination, long-running periodicity, and no obvious business owner.

**Verdict / severity bands** — | Value | Threshold | Means | Action |
|---|---:|---|---|
| Standard beacon candidate | `Connections >= 8` and `BeaconScore >= 50` | Enough repeated call-homes exist to judge cadence, and the cadence is regular enough to hunt. | Validate `Dest`, check device timeline, then find the calling process in nearby `ConnectionSuccess` telemetry. |
| Low-and-slow sleeper | `Connections >= 4`, `SpanHours >= 48`, and `BeaconScore >= 60` | Fewer calls, but spread across at least two days with a stable cadence. | Treat as stealthier; escalate faster if destination/process is unknown. |
| Interval band | `MedianSec` between `30` and `172800` seconds | Ignores ultra-fast noise and intervals longer than two days. | If you hunt very slow implants, increase `maxIntervalSec`; expect more cost/noise. |
| `regular` pattern | `Connections >= 8` and `CV <= 0.25` | Timing is consistently periodic. | Check whether the destination is a known scheduler/update endpoint. |
| `jittered` pattern | `Connections >= 8` and `CV > 0.25` with score passing via CV or IQR logic | Timing has variation but still has a repeated structure. | Consider adversary jitter; compare median interval and IQR-backed score. |

**Tunables:** `lookback = 30d`; `minRarity = 0.7` keeps rare JA4s only; `minConns = 8` sets the standard beacon floor; `minConnsLow = 4` allows low-and-slow candidates; `minIntervalSec = 30` and `maxIntervalSec = 172800` define allowed cadence; `minBeaconScore = 50` sets standard score floor; low-and-slow logic uses fixed `SpanHours >= 48` and `BeaconScore >= 60`.
**False positives:** Microsoft Delivery Optimization, AV, EDR, browser sync, and software updaters → rare-JA4 gate, minimum connection counts, interval banding, and score floor reduce but do not remove them → verify `Dest` ownership, change windows, and expected scheduled tasks/services. Cloud IP rotation → destination uses SNI before IP to avoid splitting one service across many IPs → enrich `Dest` and use `SampleRemoteIP` only as a sample. Jittered legitimate telemetry → robust IQR scoring may keep it → confirm vendor documentation before suppressing.
**Example row:** `DeviceName=WKSTN-042, ja4_=t13d201100_2b729b4bf6f3_9e7b989ebec8, Dest=198.51.100.44, BeaconScore=91, Pattern=regular, Connections=18, MedianIntervalMin=15.0, JitterCV=0.05, Rarity=0.94, SpanHours=4.3` → investigate because one host used a rare JA4 to call a raw public IP every ~15 minutes with very low jitter.
**Next step:** Enrich `Dest`, then pivot to the device timeline around `FirstSeen` and `LastSeen` to identify the initiating process. Escalate when the destination is unknown/raw IP, the process is suspicious or absent from expected software, or the same `ja4_`/`Dest` pattern appears on multiple devices.

### 05 First-seen JA4   (hunt · `wb_firstseen.kql`)
**What it detects:** JA4 client fingerprints that were absent from the baseline portion of the lookback but appeared at least three times in the most recent window.
**Hunt hypothesis:** "A newly introduced implant or tool shows up as a JA4 that never appeared in the environment baseline, then appears recently in inspected TLS telemetry."
**MITRE ATT&CK:** T1071.001 (Application layer protocol: Web protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `TimeGenerated`, `DeviceId`, `RemoteIP`, `AdditionalFields.ja4`, `AdditionalFields.server_name`; rarity-gated: no (`new == inherently rare` in this query); known-bad lookup: n/a.
**How it works:** The query uses one scan of the last `30` days and treats the last `2` days as the `newWindow`. For each JA4, it counts historic events before the new window and recent events inside it, then keeps only JA4 values with `SeenHistoric == 0` and `NewConns >= 3`. It adds simple JA4-structure notes, such as legacy TLS or no SNI, so the analyst can spot higher-risk new fingerprints; the FoxIO JA4 mapping in the Sources & validation card explains why sudden new fingerprints in stable estates are worth review.

**Sample query (excerpt):** the detection heart of `wb_firstseen.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
base
| summarize SeenHistoric = countif(TimeGenerated < ago(newWindow)),
            NewConns     = countif(TimeGenerated >= ago(newWindow)),
            NewDevices   = dcountif(DeviceId, TimeGenerated >= ago(newWindow), 4),
            Dests        = make_set_if(coalesce(sni, tostring(RemoteIP)), TimeGenerated >= ago(newWindow), 5),
            FirstSeen    = minif(TimeGenerated, TimeGenerated >= ago(newWindow)),
            LastSeen     = maxif(TimeGenerated, TimeGenerated >= ago(newWindow)) by ja4_
| where SeenHistoric == 0 and NewConns >= 3   // never in baseline (brand new) + not a one-off
| extend Spread = iff(NewDevices >= 2, "spreading (multi-host)", "single host")
| extend cipherCnt = toint(substring(ja4_, 4, 2)), extCnt = toint(substring(ja4_, 6, 2))
| extend Note = strcat(iff(substring(ja4_, 1, 2) in ("10","11","s3","s2"), "legacy-TLS ", ""),
                       iff(substring(ja4_, 3, 1) == "i", "no-SNI ", ""), iff(extCnt == 0, "no-ext ", ""),
                       iff(cipherCnt between (1 .. 3), "few-ciphers ", ""))
| project ja4_, NewDevices, NewConns, Spread, Note, Dests, FirstSeen, LastSeen
| sort by NewDevices desc, NewConns desc
```

**Output columns** — | Column | What it means |
|---|---|
| `ja4_` | The newly observed JA4 client TLS fingerprint. It identifies the TLS client handshake shape that was not seen in the earlier baseline. |
| `NewDevices` | Distinct devices that used this JA4 during the recent `newWindow`. `1` means single host; `2+` means possible spread or a legitimate rollout. |
| `NewConns` | Number of recent TLS connections using this JA4. The query requires at least `3` to suppress one-off noise. |
| `Spread` | Text label derived from `NewDevices`: `spreading (multi-host)` when `NewDevices >= 2`, otherwise `single host`. |
| `Note` | Space-separated quick flags decoded from JA4 structure: `legacy-TLS`, `no-SNI`, `no-ext`, and/or `few-ciphers`. Blank means none of those structural hints were present. |
| `Dests` | Up to five recent destinations, using SNI when available and `RemoteIP` when SNI is empty. Unknown domains, raw IPs, or newly registered domains are higher risk. |
| `FirstSeen` | First time this JA4 appeared inside the recent window. Use it to line up with installs, downloads, alerts, or user logons. |
| `LastSeen` | Most recent time this JA4 appeared. Recent or continuing activity is more urgent. |

**Reading this output:** Start with `Spread`, then `NewDevices`, `NewConns`, `Note`, and `Dests`. This panel does not emit a `Why` or `Reasons` column; the evidence is the absence from baseline plus the displayed recent spread, count, structural note, and destinations. Normal first-seen rows often come from new software, browser updates, agents, or enterprise rollouts; suspicious rows are single-host or rapidly spreading fingerprints with `legacy-TLS`, `no-SNI`, `no-ext`, `few-ciphers`, or unknown/raw-IP destinations.
**Tunables:** `lookback = 30d` defines the full baseline plus recent period; `newWindow = 2d` defines "recent"; `NewConns >= 3` suppresses one-off fingerprints. Widening `lookback` makes "first seen" stricter; widening `newWindow` catches slower rollouts but increases review volume.
**False positives:** New legitimate software, browser/library updates, endpoint-agent rollouts, or IT scripts → historic anti-join plus `NewConns >= 3` removes old and one-off JA4s, but not real rollouts → check change calendar, software inventory, signer, and whether `Dests` are expected vendor services. Small lab/test systems → no extra suppression → confirm asset role before escalating.
**Example row:** `ja4_=t13i030000_abcd1234abcd_123456789abc, NewDevices=1, NewConns=5, Spread=single host, Note="no-SNI no-ext few-ciphers", Dests=["203.0.113.77"], FirstSeen=2026-06-18 09:12Z, LastSeen=2026-06-18 10:01Z` → suspicious because a brand-new single-host JA4 made multiple recent calls to a raw IP and JA4 structure suggests a primitive or evasive TLS client.
**Next step:** Check what changed on the device at `FirstSeen` and identify the calling process. Escalate when the JA4 is unexplained, has risky `Note` flags, uses unknown/raw-IP destinations, or appears on multiple hosts without an approved rollout.

### 06 Cipher-cycling / JA4_ac   (hunt · `wb_cyclers.kql`)
**What it detects:** JA4 clients that rotate cipher choices while keeping the same JA4 a-section and c-section, which can indicate a tool cycling ciphers to evade full JA4 hash matching.
**Hunt hypothesis:** "An actor trying to avoid TLS fingerprint matching changes cipher suites, producing many full JA4 variants that collapse to one stable `JA4_ac` in Defender TLS telemetry."
**MITRE ATT&CK:** T1001 (Data obfuscation) · T1071.001 (Application layer protocol: Web protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `TimeGenerated`, `DeviceId`, `RemoteIP`, `AdditionalFields.ja4`, `AdditionalFields.server_name`; rarity-gated: no; known-bad lookup: n/a.
**How it works:** The query derives `ja4_ac` by keeping the first `10` characters of JA4 (the a-section/client shape) and the final `12`-character c-section hash, while dropping the middle cipher-hash b-section. It then counts distinct full JA4 strings that share the same `ja4_ac` and keeps rows where `DistinctJa4 >= 4`. This follows the FoxIO/GreyNoise JA4_ac idea: if only the cipher hash changes while the rest stays stable, the same tool or actor may be cycling ciphers.

**Sample query (excerpt):** the detection heart of `wb_cyclers.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | extend ja4_ac = strcat(substring(ja4_, 0, 10), "_", substring(ja4_, 24, 12))   // a + c, drop b (cipher hash)
    | project TimeGenerated, DeviceId, RemoteIP, ja4_, ja4_ac, sni;
base
| summarize DistinctJa4 = dcount(ja4_, 4), Variants = make_set(ja4_, 8), Conns = count(), Devices = dcount(DeviceId, 4),
            Dests = make_set(coalesce(sni, tostring(RemoteIP)), 5), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by ja4_ac
| where DistinctJa4 >= 4                     // same a+c but 4+ cipher variants = cipher cycling
| project ja4_ac, DistinctJa4, Devices, Conns, Dests, FirstSeen, LastSeen, Variants
| sort by DistinctJa4 desc, Conns desc
```

**Output columns** — | Column | What it means |
|---|---|
| `ja4_ac` | Actor-tracking key made from JA4 a-section plus c-section, with the cipher-hash b-section removed. Stable `ja4_ac` with many full JA4s means the client shape and extension behavior stayed stable while ciphers changed. |
| `DistinctJa4` | Number of distinct full JA4 fingerprints sharing this `ja4_ac`. The panel requires `4` or more; higher values indicate more cipher variation. |
| `Devices` | Number of distinct devices that used this `ja4_ac`. One device can be a single tool; many devices can be a scanner, rollout, or widespread actor/tooling. |
| `Conns` | Total TLS connections for the `ja4_ac` during lookback. High `Conns` means the pattern is common or active. |
| `Dests` | Up to five destination names/IPs seen for this `ja4_ac`, using SNI when available and `RemoteIP` otherwise. Shared unknown destinations strengthen the actor-tracking hypothesis. |
| `FirstSeen` | Earliest observed connection for this `ja4_ac` in the lookback. |
| `LastSeen` | Latest observed connection for this `ja4_ac` in the lookback. |
| `Variants` | Up to eight sample full JA4 strings that collapsed into the same `ja4_ac`. Compare them to confirm the b-section/cipher hash is what changed. |

**Reading this output:** Start with `DistinctJa4`, then `Devices`, `Dests`, and `Variants`. This panel does not emit a `Why` or `Reasons` column; the evidence is that `DistinctJa4 >= 4` full fingerprints share one `ja4_ac`. Normal cases can come from legitimate TLS libraries, scanners, A/B testing, or software updates; suspicious cases have many variants, unknown destinations, one or few devices, and no approved software explanation.
**Tunables:** `lookback = 30d`; `DistinctJa4 >= 4` is the cipher-cycling threshold; `Variants` shows up to `8` examples; `Dests` shows up to `5` destinations. Raising the threshold reduces benign library noise; lowering it finds weaker cycling but increases false positives.
**False positives:** Legitimate TLS libraries or scanners that negotiate different ciphers → `DistinctJa4 >= 4` avoids minor variation only → check process owner, scanner inventory, and whether `Dests` are expected. Cloud/CDN or enterprise software rollouts → no rarity gate is applied → compare `Devices`, `Conns`, and change records before escalating.
**Example row:** `ja4_ac=t13d201100_9e7b989ebec8, DistinctJa4=7, Devices=1, Conns=42, Dests=["updates.example-cdn.net", "198.51.100.55"], Variants=["t13d201100_111111111111_9e7b989ebec8", "t13d201100_222222222222_9e7b989ebec8"]` → review because one host produced many full JA4 variants that differ only in the cipher-hash portion while keeping a stable actor-tracking key.
**Next step:** Pivot to the device and destination, then identify the process generating the variants. Escalate when a non-scanner endpoint cycles ciphers to unknown destinations or when the same `ja4_ac` appears across multiple hosts without a known rollout.

### 07 JA4 rarity landscape   (hunt · `wb_landscape.kql`)
**What it detects:** This overview panel shows how many JA4/JA4S pairs fall into each rarity bucket so you can understand the environment's fingerprint distribution.
**Hunt hypothesis:** "A useful JA4 hunt has a small high-rarity population; the estate's JA4/JA4S distribution shows whether rarity thresholds will produce a manageable analyst queue."
**MITRE ATT&CK:** N/A (rarity distribution and tuning panel; it supports hunts rather than detecting one adversary behavior)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `DeviceId`, `AdditionalFields.ja4`, `AdditionalFields.ja4s`; rarity-gated: no (it calculates rarity for all pairs); known-bad lookup: n/a.
**How it works:** The query counts connections and distinct devices for every JA4/JA4S pair in the `30`-day lookback. It calculates combined rarity `R = min(host rarity, connection rarity)`, then bins `R` into `0.1`-wide buckets. The result is a compact distribution that helps choose a `minRarity` setting for the hunt panels.

**Sample query (excerpt):** the detection heart of `wb_landscape.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let pairs = materialize(ssl | summarize Conns = count(), Devs = dcount(DeviceId, 4) by ja4_, ja4s_);
let totalConns   = toscalar(pairs | summarize sum(Conns));
let totalDevices = toscalar(ssl | summarize dcount(DeviceId, 4));
pairs
| extend R = min_of(iff(totalDevices <= 1, 1.0, max_of(0.0, log(todouble(totalDevices) / todouble(Devs)) / log(todouble(totalDevices)))),
                    iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns)))))
| summarize Pairs = count() by RarityBucket = bin(R, 0.1)
| sort by RarityBucket asc
```

**Output columns** — | Column | What it means |
|---|---|
| `RarityBucket` | The lower edge of a `0.1`-wide rarity bucket created by `bin(R, 0.1)`. Example: `0.7` means `0.70 <= R < 0.80`; `0.9` means `0.90 <= R < 1.00`. Higher buckets are rarer. |
| `Pairs` | Number of distinct JA4/JA4S pairs in that bucket during lookback. This is a count of fingerprint pairs, not a count of connections or devices. |

**Reading this output:** Read from high `RarityBucket` to low. This panel does not emit a `Why` or `Reasons` column; the evidence is the bucket distribution itself. A normal enterprise often has many common pairs in lower buckets and a small number of rare pairs near `0.7..1.0`; if the high-rarity buckets are huge, Tier-1 queues will be noisy and you should raise `minRarity` or use more specific panels.
**Tunables:** `lookback = 30d`; bucket size is fixed at `0.1`; downstream `minRarity` values such as `0.7`, `0.85`, or `0.95` should be selected based on how many `Pairs` appear in the upper buckets.
**False positives:** Not applicable as an alert concept because this is a distribution panel → no suppression is applied → use it to tune rarity and validate telemetry rather than to escalate a single row.
**Example row:** `RarityBucket=0.9, Pairs=12` → there are 12 JA4/JA4S pairs with `R` from `0.90` up to but not including `1.00`; this is a small enough population to hunt manually, especially if paired with suspicious TLS evidence.
**Next step:** Use the distribution to set `minRarity` for Top prioritized leads, Suspicious rare JA4 triage, and Beaconing call-homes. Escalate nothing from this panel alone; pivot into a detection panel for row-level evidence.

### 01 Process -> JA4 library mismatch   (Hunt · `wb_mismatch.kql`)
**What it detects:** A rare public TLS client JA4 whose b-section, the 12-character TLS-library identifier at JA4 characters 11-22, contradicts the process that Microsoft Defender attributed to the connection.
**Hunt hypothesis:** "uTLS parroting, DLL injection, Go implants, or LOLBIN loaders show up as a rare JA4 b-section that does not match the initiating process in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1055 (Process Injection) · T1036 (Masquerading) · T1218 (System Binary Proxy Execution)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.server_name`, `RemoteIP`, `RemotePort`, `DeviceId`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessVersionInfoCompanyName`; rarity-gated: yes (`minRarity = 0.7`); known-bad: n/a
**How it works:** The query reads `SslConnectionInspected`, parses `ja4_`, and extracts `bsec = substring(ja4_, 11, 12)`. It computes tenant-wide JA4 rarity, keeps only rare public destinations, then joins those exact flows to `ConnectionSuccess` process attribution. It suppresses normal browser processes, Microsoft SNIs, and expected Go signers/processes, then emits only rows where `Mismatch` is non-empty.

**Sample query (excerpt):** the detection heart of `wb_mismatch.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| join kind=inner procs on DeviceId, RemoteIP, RemotePort   // procs is now small (non-browser only) -> optimizer broadcasts it instead of shuffling the SSL base (avoids the 5GB join)
| extend goExpected = (Signer has "Google" or Signer has "HashiCorp" or Signer has "Cloudflare" or Signer has "Docker" or Proc has "go" or Proc has "kubectl" or Proc has "node")
| extend Mismatch = case(
    IsBrowserMasq, strcat("Browser binary '", Proc, "' running TLS from a non-standard path (masquerade / dropped loader)"),
    Proc in~ (lolbinProcs), strcat("TLS initiated by LOLBIN script-host '", Proc, "' = a system binary that should never originate TLS (injection / loader)"),
    (bsec in (chromiumBsec)) and not (Proc in~ (chromiumProcs)), strcat("Chromium TLS library (b-section ", bsec, ") from non-browser '", Proc, "' = uTLS parroting or DLL injection into the TLS stack"),
    (bsec == firefoxBsec) and not (Proc in~ (firefoxProcs)), strcat("Firefox TLS library (b-section ", bsec, ") from non-Firefox '", Proc, "' = uTLS parroting or injection"),
    (bsec == pythonBsec) and (Proc !has "python"), strcat("Python TLS library (b-section ", bsec, ") from '", Proc, "' which is not Python = scripted TLS masquerading as another process"),
    (bsec in (goBsec)) and not(goExpected), strcat("Go TLS library (b-section ", bsec, ") from unexpected '", Proc, "' = Go-based implant or tool (e.g. Sliver)"),
    "")
| where isnotempty(Mismatch) and isPublic and not(isnotempty(sni) and sni has_any (msSni))
| extend isUserPath = (ProcFolder has "appdata" or ProcFolder hasprefix "c:\\users\\" or ProcFolder has "\\temp\\")
| summarize Conns = count(), Devices = dcount(DeviceId, 4), Dests = make_set(coalesce(sni, tostring(RemoteIP)), 6),
            ProcFolders = make_set(ProcFolder, 4), AnyUserPath = max(isUserPath), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by Mismatch, Proc, bsec, ja4_
| extend Severity = case(Proc in~ (lolbinProcs) or AnyUserPath, "High", "Medium")
| project Severity, Mismatch, Proc, bsec, ja4_, Devices, Conns, AnyUserPath, ProcFolders, Dests, FirstSeen, LastSeen
| sort by Severity asc, Devices asc, Conns asc
```
**Output columns** —

| Column | What it means |
|---|---|
| `Severity` | Query-assigned band: `High` when the process is a listed LOLBIN/script host or any observed process path is a user/temp path; `Medium` for the other rare mismatch cases. |
| `Mismatch` | Plain-English evidence string. It names the contradicted TLS library, includes the b-section value, and states the suspected mechanism such as uTLS parroting, DLL injection, scripted TLS masquerading, or a Go implant/tool. |
| `Proc` | Lowercase initiating process file name from `ConnectionSuccess`, such as `rundll32.exe` or `curl.exe`. |
| `bsec` | JA4 b-section, a 12-character library fingerprint. The query compares it to embedded Chromium, Firefox, Python, and Go b-section values. |
| `ja4_` | Full client JA4 fingerprint observed in the TLS ClientHello. Same value means the same client TLS shape/library combination. |
| `Devices` | Approximate distinct endpoint count (`dcount(DeviceId, 4)`) that produced this mismatch. Lower is rarer; more than one device can indicate a tool or campaign. |
| `Conns` | Number of inspected TLS connections represented by the row. |
| `AnyUserPath` | True when at least one process folder contains `appdata`, starts with `c:\users\`, or contains `\temp\`. User/temp paths are suspicious for dropped loaders. |
| `ProcFolders` | Up to 4 sampled initiating-process folders. Use this to verify whether the binary is installed normally or running from a user-writable location. |
| `Dests` | Up to 6 sampled destination names, using SNI when present and otherwise `RemoteIP`. Microsoft destinations are already suppressed. |
| `FirstSeen` | Earliest observed TLS event in the lookback for this grouped mismatch. |
| `LastSeen` | Latest observed TLS event in the lookback for this grouped mismatch. |

**Reading this output:** Read `Mismatch` first; it already carries the plain-English reasoning, including the b-section value and mechanism. Then read `Severity`, `Proc`, `AnyUserPath`, and `ProcFolders` to decide whether the mismatch is a LOLBIN, dropped binary, or unusual but installed app. Normal browser-to-browser-library traffic and Microsoft SNIs are filtered out; suspicious rows are rare public flows where the TLS library and attributed process disagree.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `High` | `Proc` is in `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `cmd.exe`, `msiexec.exe`, or `hh.exe`; or `AnyUserPath` is true. | A rare TLS-library/process contradiction involves a script-host LOLBIN or a user/temp path. | Escalate to Tier-2/IR after collecting process tree, file hash, signer, command line, and destination context. |
| `Medium` | `Mismatch` is non-empty after rarity, public-destination, Microsoft-SNI, browser, and Go-expected suppressions, but the high conditions are false. | The process/library relationship is still anomalous, but the process/path context is less immediately malicious. | Validate signer and software owner; escalate if the process is unapproved, unsigned, newly created, or contacting an unknown destination. |

**Tunables:** `lookback = 30d` → wider history finds older mismatches but costs more; `minRarity = 0.7` → higher values keep fewer, rarer JA4s; `chromiumProcs` / `firefoxProcs` → controls normal browser/WebView suppression; `lolbinProcs` → controls the High severity process list; `chromiumBsec`, `firefoxBsec`, `pythonBsec`, `goBsec` → embedded library fingerprints; `msSni` → Microsoft destination suppression; `goExpected` signer/process logic → reduces false positives from legitimate Go software.
**False positives:** WebView2/Electron apps → Chromium and Firefox process allowlists plus normal-browser drop → confirm signer and install path. Legitimate Go tools such as Google, HashiCorp, Cloudflare, Docker, `kubectl`, or `node` → `goExpected` suppression → verify unlisted Go binaries with owner and deployment records. Microsoft service traffic → Microsoft SNI suppression → residual check is any non-Microsoft `Dests` still shown.
**Example row:** "`Severity=High`; `Mismatch=Go TLS library (b-section 9dc949149365) from unexpected 'rundll32.exe' = Go-based implant or tool (e.g. Sliver)`; `Devices=1`; `AnyUserPath=true` → High because the query makes any LOLBIN or user/temp-path mismatch high severity."
**Next step:** Open the device timeline for the `Proc` and `ProcFolders`, collect hash/signer/command line, and pivot on `ja4_`, `bsec`, and `Dests`. Escalate when the process is a LOLBIN, user-path binary, unsigned/unowned binary, or has no approved business owner.

### 02 C2 TLS-shape / Cobalt Strike   (Hunt · `wb_c2shape.kql`)
**What it detects:** Cobalt Strike WinINET/TeamServer fingerprints and rare TLS 1.2 ClientHello shapes with no ALPN from suspicious LOLBIN or loader processes.
**Hunt hypothesis:** "Malleable-C2 beacons that cannot fully change their TLS stack show up as exact Cobalt Strike JA4/JA4S values or as rare TLS 1.2-with-no-ALPN ClientHellos from script-host processes in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1071.001 (Web Protocols) · T1218 (System Binary Proxy Execution)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `RemoteIP`, `RemotePort`, `DeviceId`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`; rarity-gated: partial (exact Cobalt Strike branch is not gated; TLS-shape branch requires `minRarity = 0.7`); known-bad: n/a (embedded Cobalt Strike constants, not the opt-in lookup)
**How it works:** The query parses `tlsVer = substring(ja4_, 1, 2)`, `alpn = substring(ja4_, 8, 2)`, and `csec = substring(ja4_, 24, 12)`. Exact Cobalt Strike hits fire when the client c-section is `16bbda4055b2` or the server JA4S is `t120300_c030_52d195ce1d92`; the `Why` text names FoxIO `ja4plus-mapping` for the documented client fingerprint. Non-exact shape hits require TLS 1.2, no ALPN (`alpn == "00"`), a rare JA4, a suspicious process, a public destination, and not a Microsoft SNI.

**Sample query (excerpt):** the detection heart of `wb_c2shape.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | extend R = min_of(Rhost, Rconn) | where R >= minRarity | project ja4_);
// …
union b1, b2
| extend isUserPath = (ProcFolder has "appdata" or ProcFolder hasprefix "c:\\users\\" or ProcFolder has "\\temp\\")
| extend isMsDest  = (isnotempty(sni) and sni has_any (msSni))
| where exactCs or (shape and suspProc and not(isMsDest))
| extend Why = strcat(iff(csec == csCsec, strcat("client TLS c-section ", csec, " = documented Cobalt Strike WinINET beacon fingerprint (FoxIO ja4plus-mapping); "), ""),
                      iff(ja4s_ == csJa4s, strcat("server JA4S ", ja4s_, " = Cobalt Strike default TeamServer response; "), ""),
                      iff(shape, "ClientHello is TLS 1.2 with no ALPN = malleable-C2 default shape (real browsers negotiate ALPN h2); ", ""),
                      iff(suspProc, strcat("initiating process '", Proc, "' is a LOLBIN/script-host that should not originate TLS; "), ""),
                      iff(isUserPath, "process runs from a user/temp path (not a normal install location); ", ""))
| summarize Conns = count(), Devices = dcount(DeviceId, 4), Procs = make_set(Proc, 5), Dests = make_set(coalesce(sni, tostring(RemoteIP)), 6),
            AnyExactCs = max(exactCs), AnyUserPath = max(isUserPath), Why = take_any(Why), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by ja4_, ja4s_
| extend Verdict = iff(AnyExactCs, "CRITICAL - Cobalt Strike fingerprint", "HIGH - C2 TLS shape + suspicious process")
| project Verdict, ja4_, ja4s_, Why, Procs, Devices, Conns, AnyUserPath, Dests, FirstSeen, LastSeen
| sort by Verdict asc, Devices asc, Conns asc
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | `CRITICAL - Cobalt Strike fingerprint` for exact Cobalt Strike values; otherwise `HIGH - C2 TLS shape + suspicious process`. |
| `ja4_` | Full client JA4 fingerprint from the ClientHello. |
| `ja4s_` | Server JA4S fingerprint from the ServerHello when present. JA4S identifies the responding server TLS stack. |
| `Why` | Plain-English evidence string. It can state that the client c-section is the documented Cobalt Strike WinINET beacon fingerprint, the server JA4S is the default Cobalt Strike TeamServer response, the ClientHello is TLS 1.2 with no ALPN, the process is a LOLBIN/script host, or the process runs from a user/temp path. |
| `Procs` | Up to 5 initiating process names seen for this JA4/JA4S pair. |
| `Devices` | Approximate distinct endpoint count producing this JA4/JA4S pair. |
| `Conns` | Number of matching inspected TLS connections. |
| `AnyUserPath` | True when any matched process folder contains `appdata`, starts with `c:\users\`, or contains `\temp\`. |
| `Dests` | Up to 6 sampled SNI names or remote IPs. |
| `FirstSeen` | Earliest matching event in the lookback. |
| `LastSeen` | Latest matching event in the lookback. |

**Reading this output:** Read `Why` first; it already explains the evidence in analyst language, including the FoxIO-documented Cobalt Strike c-section when present. `CRITICAL` means an exact Cobalt Strike fingerprint was observed on any process, not just a LOLBIN. `HIGH` means the exact known fingerprint was not present, but the row still has the malleable-C2 default shape: TLS 1.2, no ALPN, rare JA4, suspicious process, and non-Microsoft public destination.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `CRITICAL - Cobalt Strike fingerprint` | `csec == "16bbda4055b2"` or `ja4s_ == "t120300_c030_52d195ce1d92"`. | The TLS client or server fingerprint matches embedded Cobalt Strike values; the client mapping is documented by FoxIO `ja4plus-mapping`. | Treat as active C2 until disproven. Escalate immediately, preserve host evidence, and block/contain according to local playbook. |
| `HIGH - C2 TLS shape + suspicious process` | Not exact CS, but `tlsVer == "12"`, `alpn == "00"`, JA4 rarity `R >= 0.7`, process is in the suspicious process list, destination is public, and SNI is not Microsoft. | A rare LOLBIN/script-host flow has the malleable-C2 TLS shape; real browsers normally negotiate ALPN such as `h2`. | Investigate promptly; escalate if process execution is unexplained, destination is unknown, or other C2 indicators exist. |

**Tunables:** `lookback = 30d` → search horizon; `minRarity = 0.7` → applies only to the shape branch; `csJa4s` and `csCsec` → exact Cobalt Strike constants; `suspProcs` → LOLBIN/loader list (`rundll32.exe`, `powershell.exe`, `msbuild.exe`, etc.); `msSni` → Microsoft destination suppression for the shape branch; display cap `take 200` → workbook row limit.
**False positives:** Legacy WinHTTP/enterprise scripts using TLS 1.2 without ALPN → suppressed unless the process is suspicious, public, non-Microsoft, and rare → verify the script owner and command line. Security/admin tooling on LOLBIN-like hosts → rarity gate and process list limit volume → validate change records and destination ownership. Exact CS-like test labs → no suppression by design → confirm whether the host is an approved red-team system before closing.
**Example row:** "`Verdict=CRITICAL - Cobalt Strike fingerprint`; `Why=client TLS c-section 16bbda4055b2 = documented Cobalt Strike WinINET beacon fingerprint (FoxIO ja4plus-mapping); ClientHello is TLS 1.2 with no ALPN...`; `Procs=[rundll32.exe]` → Critical because either the exact client c-section or exact server JA4S is enough to trigger the critical branch."
**Next step:** For `CRITICAL`, escalate immediately and pivot on `ja4_`, `ja4s_`, `Procs`, and `Dests`. For `HIGH`, collect process tree, command line, parent process, signer, and destination reputation; escalate if there is no approved administrative explanation.

### 03 Common client -> rare server JA4S   (Hunt · `wb_serverrare.kql`)
**What it detects:** Common client JA4s, such as browsers or WinHTTP, connecting to rare public server JA4S fingerprints with suspicious certificates.
**Hunt hypothesis:** "C2 that hides behind a normal client TLS library shows up as a common client JA4 reaching a rare server JA4S with a self-signed or obscure certificate in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1071.001 (Web Protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `AdditionalFields.issuer`, `AdditionalFields.subject`, `RemoteIP`, `DeviceId`; rarity-gated: no (uses explicit common-client and rare-server thresholds instead of `minRarity`); known-bad: n/a
**How it works:** The query keeps public TLS events that contain both client `ja4_` and server `ja4s_`. It computes client prevalence by JA4 and server prevalence by JA4S, then requires the client to be common (`cDevs >= max(3, totalDevs * 0.10)`) and the server to be rare (`sDevs <= 2` and `sConns <= 50`). It also requires a suspicious certificate signal: self-signed (`issuer == subject`) or an issuer outside the embedded known-CA list.

**Sample query (excerpt):** the detection heart of `wb_serverrare.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| lookup clientPrev on ja4_
| lookup serverPrev on ja4s_
| where cDevs >= max_of(3, toint(totalDevs * 0.10))    // client fingerprint is COMMON across the estate
| where sDevs <= 2 and sConns <= 50                     // server fingerprint is RARE
| where AnySelfSigned == 1 or AnyObscureIssuer == 1     // legit public-CA servers are NOT C2 - require a suspicious cert
| extend Verdict = case(sDevs <= 1 and AnySelfSigned == 1, "HIGH - common client to singleton self-signed server",
                        sDevs <= 1,                        "HIGH - common client to singleton server TLS",
                                                           "MEDIUM - common client to rare server TLS")
| project Verdict, ClientJA4 = ja4_, ServerJA4S = ja4s_, ClientDevices = cDevs, ServerDevices = sDevs,
          ServerConns = sConns, Devices, Conns, SelfSigned = AnySelfSigned, Dests, Issuers, FirstSeen, LastSeen
| sort by ServerDevices asc, ClientDevices desc
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | Severity text based on how rare the server JA4S is and whether any certificate is self-signed. |
| `ClientJA4` | Common client JA4 fingerprint. The client looks normal across the estate. |
| `ServerJA4S` | Rare server TLS fingerprint. This is the server-side signal that may expose C2 infrastructure. |
| `ClientDevices` | Approximate number of devices in the tenant that used `ClientJA4`. Must be at least 3 or 10% of total devices, whichever is larger. |
| `ServerDevices` | Approximate number of devices that saw `ServerJA4S` across the tenant. `1` means singleton; `2` still qualifies as rare. |
| `ServerConns` | Total connections for that `ServerJA4S`; must be 50 or fewer. |
| `Devices` | Approximate number of devices represented by this specific `ClientJA4` + `ServerJA4S` pair. |
| `Conns` | Number of inspected TLS connections for this pair. |
| `SelfSigned` | `1` when any certificate had the same issuer and subject, meaning self-signed; `0` otherwise. |
| `Dests` | Up to 8 sampled SNI names or remote IPs. |
| `Issuers` | Up to 5 sampled certificate issuers. Obscure issuers are not in the query's known public CA list. |
| `FirstSeen` | Earliest event for this client/server fingerprint pair. |
| `LastSeen` | Latest event for this client/server fingerprint pair. |

**Reading this output:** Read `Verdict`, `ServerDevices`, `SelfSigned`, and `Issuers` first. A normal common browser JA4 is not suspicious by itself; the suspicious signal is that it reaches a rare JA4S server with self-signed or obscure certificate metadata. There is no separate `Why` column in this panel, so the `Verdict` text plus `SelfSigned` and `Issuers` provide the plain-English evidence.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - common client to singleton self-signed server` | After all filters, `sDevs <= 1` and `AnySelfSigned == 1`. | A normal-looking client reached a server TLS stack seen on only one device, and at least one certificate was self-signed. | Escalate unless destination ownership is known and approved; collect certificate, destination, and host process context. |
| `HIGH - common client to singleton server TLS` | After all filters, `sDevs <= 1`, but self-signed is not true. | A common client reached a singleton server JA4S with an obscure issuer. | Investigate as likely C2 or unmanaged service; escalate if unowned. |
| `MEDIUM - common client to rare server TLS` | After all filters, `sDevs == 2`. | The server JA4S is rare but not singleton; certificate metadata is still suspicious because the query requires self-signed or obscure issuer. | Validate destination and certificate; escalate if both devices have no business relationship to the service. |

**Tunables:** `lookback = 30d` → prevalence window; common-client threshold `cDevs >= max(3, totalDevs * 0.10)` → raises/lowers what counts as normal client JA4; rare-server thresholds `sDevs <= 2` and `sConns <= 50` → define rare JA4S; `knownCA` list → controls which issuers are treated as common public CAs; certificate requirement `AnySelfSigned == 1 or AnyObscureIssuer == 1` → suppresses normal public-CA services.
**False positives:** Small SaaS or partner service with a private/obscure CA → public-only plus suspicious-certificate requirement still allows it → verify contract, domain owner, and certificate chain. Lab or internal service exposed publicly → server rarity and self-signed logic can flag it → confirm asset inventory and expected clients. New vendor rollout → common-client/rare-server shape can appear briefly → check change tickets and first-seen timing.
**Example row:** "`Verdict=HIGH - common client to singleton self-signed server`; `ClientDevices=1200`; `ServerDevices=1`; `ServerConns=9`; `SelfSigned=1`; `Issuers=[CN=example]` → High because the client JA4 is common, but the server JA4S is singleton and self-signed."
**Next step:** Pivot on `ServerJA4S`, `Dests`, and `Issuers`; identify the process and user on the affected device. Escalate when the destination is not an approved service, the certificate is self-signed/unknown, or the device has other suspicious activity.

### 04 Rare JA4 on non-standard TLS port   (Hunt · `wb_oddport.kql`)
**What it detects:** Rare public client JA4 fingerprints using inspected TLS on destination ports outside the normal TLS service list, especially known-abused C2 or tunnel ports.
**Hunt hypothesis:** "A C2 listener or TLS tunnel shows up as a rare JA4 connecting over TLS to a public non-standard destination port in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1572 (Protocol Tunneling) · T1071.001 (Web Protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `RemoteIP`, `RemotePort`, `DeviceId`; rarity-gated: yes (`minRarity = 0.7`); known-bad: n/a
**How it works:** The query keeps public TLS events, computes tenant-wide JA4 rarity, and joins only JA4s with `R >= 0.7`. It removes common TLS service ports (`443`, `8443`, `9443`, mail TLS ports, DoT `853`, FTPS `990`, SIP TLS `5061`, and LDAPS `636`). It then marks rows High if any observed port is in the attacker-common `suspPorts` list.

**Sample query (excerpt):** the detection heart of `wb_oddport.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let rare = perJa4
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(Devs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R;
ssl
| where RemotePort !in (benignPorts)
| lookup kind=inner rare on ja4_
| summarize Conns = count(), Devices = dcount(DeviceId, 4), Ports = make_set(RemotePort, 12),
            SNIs = make_set(sni, 8), Dests = make_set(coalesce(sni, tostring(RemoteIP)), 8),
            AnySuspPort = max(toint(RemotePort in (suspPorts))), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by ja4_, ja4s_, RemoteIP, R
| extend Verdict = case(AnySuspPort == 1, "HIGH - rare JA4 on known-abused TLS port",
                        "MEDIUM - rare JA4 on non-standard TLS port")
| project Verdict, JA4 = ja4_, ServerJA4S = ja4s_, RemoteIP, Ports, Rarity = round(R, 2), Devices, Conns, SNIs, Dests, FirstSeen, LastSeen
| sort by Verdict asc, Rarity desc, Devices asc
| take 200
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | `HIGH` for rare JA4 on a known-abused TLS port; `MEDIUM` for rare JA4 on another non-standard TLS port. |
| `JA4` | Full client JA4 fingerprint. |
| `ServerJA4S` | Server TLS fingerprint for the destination. |
| `RemoteIP` | Public destination IP receiving the TLS connection. |
| `Ports` | Up to 12 destination ports observed for this JA4/server/IP grouping. These are all outside the benign port list. |
| `Rarity` | Rounded rarity score `R = min(Rhost, Rconn)`. `0.70` is the minimum shown; values closer to `1.00` mean fewer devices or connections used the JA4. |
| `Devices` | Approximate distinct endpoint count that used this JA4 to this server/IP grouping. |
| `Conns` | Number of inspected TLS connections in the group. |
| `SNIs` | Up to 8 sampled SNI names from the TLS handshake. Empty SNI can be suspicious, but this panel does not require or score it. |
| `Dests` | Up to 8 sampled destination names, using SNI when present and otherwise `RemoteIP`. |
| `FirstSeen` | Earliest observed connection in the lookback. |
| `LastSeen` | Latest observed connection in the lookback. |

**Reading this output:** Read `Ports`, `Verdict`, and `Rarity` first. Normal TLS ports are already suppressed, so every row is a rare JA4 on an unusual public TLS port; `HIGH` means at least one port is in the query's known-abused list. There is no separate `Why` column, so the `Verdict` text and `Ports` column are the plain-English evidence.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - rare JA4 on known-abused TLS port` | `AnySuspPort == 1`, meaning any observed port is one of `4443`, `4444`, `4445`, `8080`, `8081`, `9001`, `10443`, `50050`, `1080`, `8000`, `8888`, `31337`, `6666`, or `7777`. | A rare client TLS fingerprint is using a port commonly seen with C2 listeners, tunnels, or attacker infrastructure. | Escalate after confirming the process and destination are not approved. Block/contain if destination is unknown or malicious. |
| `MEDIUM - rare JA4 on non-standard TLS port` | JA4 rarity `R >= 0.7`, destination is public, `RemotePort` is not in the benign port list, and no port is in `suspPorts`. | The TLS port is unusual but not one of the explicitly known-abused ports. | Validate service owner, protocol, and business justification; escalate if unowned or paired with suspicious process context. |

**Tunables:** `lookback = 30d` → search horizon; `minRarity = 0.7` → rare JA4 cutoff; `benignPorts` → normal TLS-service port suppression (`443`, `8443`, `9443`, `465`, `587`, `993`, `995`, `853`, `990`, `5061`, `636`); `suspPorts` → ports that drive High severity; `take 200` → workbook display cap.
**False positives:** Legitimate TLS services on alternate ports → benign port list suppresses common mail, DoT, FTPS, SIP TLS, and LDAPS → verify application owner and service banner. Security tools, proxies, or developer services on custom ports → rarity and public-only filters reduce fleet noise → check deployment records and whether the port is expected. New SaaS endpoint using an unusual port → SNI/Dests reveal the service → confirm vendor documentation.
**Example row:** "`Verdict=HIGH - rare JA4 on known-abused TLS port`; `Ports=[4444]`; `Rarity=0.94`; `Devices=1`; `Conns=6` → High because port 4444 is in `suspPorts` and the JA4 passed the rarity gate."
**Next step:** Pivot from `JA4`, `RemoteIP`, and `Ports` to the initiating process and device timeline. Escalate when the port has no approved owner, the process is a LOLBIN/user-path binary, or the same JA4 appears in other C2 panels.

### 05 Fleet-velocity spike   (Hunt · `wb_velocity.kql`)
**What it detects:** A JA4 fingerprint that jumps from zero or near-zero hosts to many hosts within recent 6-hour bins.
**Hunt hypothesis:** "A worm, actor-deployed tool, or supply-chain push shows up as sudden host-count growth for one JA4 in 6-hour `DeviceNetworkEvents` bins."
**MITRE ATT&CK:** T1105 (Ingress Tool Transfer) · T1195 (Supply Chain Compromise)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.server_name`, `RemoteIP`, `DeviceId`, `TimeGenerated`; rarity-gated: no; known-bad: n/a
**How it works:** The query groups TLS events by `ja4_` and 6-hour `tbin`, counting distinct hosts (`Hosts`) and connections (`Conns`). It compares each JA4's current bin to its previous bin (`BaselineHosts`) and keeps only bins in the last `recentWindow = 3d` where `BaselineHosts <= 2`, `Hosts >= 8`, and `Growth >= 6`. This detects propagation speed, not just first-seen novelty.

**Sample query (excerpt):** the detection heart of `wb_velocity.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
bins
| order by ja4_ asc, tbin asc
| serialize
| extend pHosts = prev(Hosts), pJa4 = prev(ja4_)
| extend BaselineHosts = iff(ja4_ == pJa4, coalesce(pHosts, 0), 0)
| extend Growth = Hosts - BaselineHosts
| where tbin > ago(recentWindow)
| where BaselineHosts <= 2 and Hosts >= 8 and Growth >= 6
| extend Verdict = case(BaselineHosts == 0, "HIGH - JA4 appeared on many hosts at once (zero baseline)",
                        "HIGH - JA4 rapidly spread across the fleet")
| project Verdict, JA4 = ja4_, SpikeTime = tbin, HostsNow = Hosts, HostsBefore = BaselineHosts, Growth, Conns, Dests
| sort by Growth desc, SpikeTime desc
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | High-severity explanation: either the JA4 appeared on many hosts from zero baseline or rapidly spread from a small baseline. |
| `JA4` | Client JA4 fingerprint whose host count spiked. |
| `SpikeTime` | Start time of the 6-hour bin where the spike was detected. |
| `HostsNow` | Approximate distinct device count in the spike bin. Must be at least `8`. |
| `HostsBefore` | Approximate distinct device count in the previous observed bin for the same JA4. Must be `0`, `1`, or `2`. |
| `Growth` | `HostsNow - HostsBefore`. Must be at least `6`. |
| `Conns` | Number of inspected TLS connections for the JA4 in the spike bin. |
| `Dests` | Up to 6 sampled SNI names or remote IPs reached by the JA4 during the spike bin. |

**Reading this output:** Read `SpikeTime`, `HostsBefore`, `HostsNow`, and `Growth` first. Normal new software rollouts can also spike, so the key question is whether the timing aligns with an approved deployment. This panel has no `Why` column; the `Verdict` text and the three host-count columns carry the evidence and explain the number jump.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - JA4 appeared on many hosts at once (zero baseline)` | `tbin > ago(3d)`, `BaselineHosts == 0`, `Hosts >= 8`, and `Growth >= 6`. | The JA4 was not seen in the previous bin and then appeared on many hosts at once. | Check for approved deployment first; if none exists, escalate as possible worm, mass tool push, or supply-chain activity. |
| `HIGH - JA4 rapidly spread across the fleet` | `tbin > ago(3d)`, `BaselineHosts` is `1` or `2`, `Hosts >= 8`, and `Growth >= 6`. | The JA4 existed on very few hosts and then spread quickly. | Validate deployment/change records and affected host list; escalate if unapproved or paired with suspicious destinations/processes. |

**Tunables:** `lookback = 30d` → historical bins available for previous-host comparison; `recentWindow = 3d` → only recent spikes are shown; `bin(TimeGenerated, 6h)` → spike resolution; `BaselineHosts <= 2` → near-zero baseline definition; `Hosts >= 8` → minimum current spread; `Growth >= 6` → minimum jump size; `take 200` → workbook display cap.
**False positives:** Approved software rollout or auto-update → spike thresholds intentionally catch mass deployment → check change tickets, software distribution logs, and package owner. Security agent update → many hosts and common destinations may appear → confirm vendor JA4/destinations. Short-lived lab/test deployment → recent-window filter shows it → verify test scope and affected devices.
**Example row:** "`Verdict=HIGH - JA4 appeared on many hosts at once (zero baseline)`; `HostsBefore=0`; `HostsNow=24`; `Growth=24`; `SpikeTime=2026-06-18 12:00` → High because the previous bin had no hosts and the current 6-hour bin exceeded both host and growth thresholds."
**Next step:** Export the affected devices and `Dests`, then check deployment/change systems. Escalate when no approved rollout explains the timing, the destinations are unknown, or the same JA4 appears in rare/destination/C2 panels.

### 06 Encrypted-DNS C2 DoH/DoT   (Hunt · `wb_doh.kql`)
**What it detects:** DNS-over-TLS or DNS-over-HTTPS from a public TLS flow attributed to a non-system, non-browser process.
**Hunt hypothesis:** "Malware hiding C2 name resolution or the C2 channel inside encrypted DNS shows up as JA4 ALPN `dt` or known public DoH provider destinations from an unexpected process in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1572 (Protocol Tunneling) · T1071.004 (DNS)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.server_name`, `AdditionalFields.next_protocol`, `RemoteIP`, `RemotePort`, `DeviceId`, `DeviceName`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessVersionInfoCompanyName`; rarity-gated: no; known-bad: n/a (known DoH providers are protocol destinations, not malware indicators)
**How it works:** The query parses `alpn = substring(ja4_, 8, 2)` and treats `alpn == "dt"` or `next_protocol == "dot"` as DNS-over-TLS, a hard protocol tell. It also detects DNS-over-HTTPS by matching SNI or IP against embedded public DoH provider lists such as Cloudflare, Google, Quad9, OpenDNS, NextDNS, AdGuard, Mullvad, and others. It joins to process attribution, suppresses expected Windows resolver/system processes and browsers, then scores LOLBIN, user-path, and unattributed cases.

**Sample query (excerpt):** the detection heart of `wb_doh.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| extend isLolbin   = (Proc in~ (lolbins))
| extend isUserPath = (ProcFolder has "appdata" or ProcFolder hasprefix "c:\\users\\" or ProcFolder has "\\temp\\" or ProcFolder has "\\downloads\\")
| extend Signal = case(isDot, "DNS-over-TLS (dt ALPN - hard tell)", isDoh, "DoH to known provider (SNI/IP match)", "encrypted DNS")
| summarize Devices = dcount(DeviceId, 4), Conns = count(), Procs = make_set(Proc, 8),
            SampleDevices = make_set(DeviceName, 4), Dests = make_set(coalesce(sni, tostring(RemoteIP)), 8),
            AnyLolbin = max(isLolbin), AnyUserPath = max(isUserPath), AnyUnattrib = max(Proc == "(unattributed)"),
            Signal = take_any(Signal), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by ja4_
| extend Verdict = case(
    AnyLolbin,   "HIGH - encrypted DNS from a LOLBIN (DNS C2 via DoH/DoT)",
    AnyUserPath, "HIGH - encrypted DNS from a user-path binary (DNS C2 vector)",
    AnyUnattrib, "MEDIUM - unattributed DoH/DoT (possible injected code)",
                 "MEDIUM - non-system, non-browser process using encrypted DNS")
| project Verdict, JA4 = ja4_, Signal, Procs, Dests, Devices, Conns, AnyLolbin, AnyUserPath, SampleDevices, FirstSeen, LastSeen
| sort by AnyLolbin desc, AnyUserPath desc, Devices asc
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | Severity and reason based on process context: LOLBIN, user-path binary, unattributed, or other non-system/non-browser process. |
| `JA4` | Client JA4 fingerprint for the encrypted-DNS TLS connection. |
| `Signal` | Plain-English protocol evidence: `DNS-over-TLS (dt ALPN - hard tell)` or `DoH to known provider (SNI/IP match)`. |
| `Procs` | Up to 8 initiating process names. Expected system resolver and browser processes are already filtered out. |
| `Dests` | Up to 8 sampled DoH/DoT destination names or IPs. |
| `Devices` | Approximate distinct endpoint count. |
| `Conns` | Number of inspected encrypted-DNS TLS connections. |
| `AnyLolbin` | True when any process is in the query's LOLBIN list, including `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `powershell.exe`, `curl.exe`, or similar. |
| `AnyUserPath` | True when any process folder contains `appdata`, starts with `c:\users\`, contains `\temp\`, or contains `\downloads\`. |
| `SampleDevices` | Up to 4 endpoint names that produced the row. |
| `FirstSeen` | Earliest matching encrypted-DNS event. |
| `LastSeen` | Latest matching encrypted-DNS event. |

**Reading this output:** Read `Signal`, `Procs`, and `Verdict` first. The `Signal` column already explains whether the row is DoT identified by JA4 ALPN `dt` or DoH identified by a known-provider SNI/IP match. Normal Windows resolver (`svchost.exe`, `system`, and related processes) and browsers are suppressed; suspicious rows are non-system, non-browser processes using encrypted DNS, especially LOLBINs or user-path binaries. The MITRE framing is T1572 plus T1071.004 because encrypted DNS can tunnel or carry C2 over DNS-like protocols.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - encrypted DNS from a LOLBIN (DNS C2 via DoH/DoT)` | `AnyLolbin == true`. | A script-host or dual-use binary is using encrypted DNS. | Escalate quickly; collect process tree, command line, file hash, and destination. |
| `HIGH - encrypted DNS from a user-path binary (DNS C2 vector)` | No LOLBIN condition, but `AnyUserPath == true`. | A binary running from a user-writable path is using DoH/DoT. | Investigate as likely unapproved tooling or malware; escalate if unsigned/unowned. |
| `MEDIUM - unattributed DoH/DoT (possible injected code)` | No LOLBIN/user-path condition, but `AnyUnattrib == true` internally because the process could not be attributed. | TLS showed encrypted DNS, but `ConnectionSuccess` did not identify a process; injection or telemetry gap is possible. | Pivot on device and network timeline; escalate if no benign source is found. |
| `MEDIUM - non-system, non-browser process using encrypted DNS` | DoH/DoT signal remains after excluding system DNS processes and browsers, with none of the higher conditions true. | An unusual process is using encrypted DNS. | Verify whether the application is sanctioned for DoH/DoT; escalate if not approved. |

**Tunables:** `lookback = 30d` → search horizon; `dohSnIs` → known public DoH provider names; `dohIPs` → known public resolver IPs; `systemDnsProcs` → expected OS resolver processes; `browserProcs` → expected native DoH browser processes; `lolbins` → drives High severity for dual-use binaries; user-path expression → controls path-based High severity.
**False positives:** Approved privacy/VPN/DNS client → non-system process may be expected → verify software owner, signer, and policy exception. Browser/native DoH → browser process suppression applied → residual check is whether `Procs` contains a browser-like helper not listed. Security product DNS inspection → system/browser suppression may not include every agent → validate signer and vendor documentation. Unattributed flows → left outer join can leave process blank → pivot in device timeline before closing.
**Example row:** "`Verdict=HIGH - encrypted DNS from a LOLBIN (DNS C2 via DoH/DoT)`; `Signal=DNS-over-TLS (dt ALPN - hard tell)`; `Procs=[powershell.exe]`; `Dests=[dns.google]` → High because `AnyLolbin` is true and JA4 ALPN `dt` identifies DNS-over-TLS."
**Next step:** Confirm whether the process is approved to use encrypted DNS. Escalate when the process is a LOLBIN, user-path binary, unsigned/unowned binary, or any endpoint policy forbids DoH/DoT.

### 07 Rare JA4 -> many destinations   (Hunt · `wb_fanout.kql`)
**What it detects:** One rare non-browser client JA4 fanning out to many distinct public IPs or SNIs.
**Hunt hypothesis:** "An implant using domain/IP rotation, DGA, or proxy hopping shows up as one rare JA4 contacting many public destinations in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1568 (Dynamic Resolution) · T1090 (Proxy)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `RemoteIP`, `DeviceId`; rarity-gated: yes (`minRarity = 0.7`); known-bad: n/a
**How it works:** The query keeps public TLS events, computes tenant-wide rarity for each JA4, and keeps JA4s with `R >= 0.7`. It removes browser b-sections so normal browsers do not dominate fan-out. It summarizes destination spread by counting distinct IPs and distinct SNIs, then uses `DestSpread = max(IPs, SNIs)` to catch either IP rotation or name rotation.

**Sample query (excerpt):** the detection heart of `wb_fanout.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let rare = perJa4
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(Devs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R;
// …
| extend DestSpread = max_of(IPs, SNIs)
| where DestSpread >= 8                                  // one rare fingerprint reaching many distinct addresses
| extend Verdict = case(DestSpread >= 25, "HIGH - rare JA4 rotating across many destinations (C2 infra rotation / DGA)",
                        "MEDIUM - rare JA4 spread across multiple destinations")
| project Verdict, JA4 = ja4_, DestSpread, DistinctIPs = IPs, DistinctSNIs = SNIs, Devices, Conns,
          Rarity = round(R, 2), ServerJA4S, Dests, FirstSeen, LastSeen
| sort by DestSpread desc, Rarity desc
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | `HIGH` for very large destination spread; `MEDIUM` for lower but still suspicious spread. |
| `JA4` | Rare non-browser client JA4 fingerprint doing the fan-out. |
| `DestSpread` | `max(DistinctIPs, DistinctSNIs)`. This is the main number: how many distinct destinations the JA4 reached by IP or by SNI, whichever is larger. |
| `DistinctIPs` | Approximate count of distinct public remote IPs contacted by this JA4. |
| `DistinctSNIs` | Approximate count of distinct SNI names contacted by this JA4. |
| `Devices` | Approximate distinct endpoint count using this JA4. A single or few devices with high spread can indicate one implant rotating infrastructure. |
| `Conns` | Number of inspected TLS connections for this JA4. |
| `Rarity` | Rounded tenant rarity score. `0.70` is the minimum; closer to `1.00` means the JA4 is less common. |
| `ServerJA4S` | Up to 5 sampled server JA4S fingerprints reached by the client JA4. Multiple values can indicate varied infrastructure. |
| `Dests` | Up to 12 sampled SNI names or remote IPs. |
| `FirstSeen` | Earliest observed fan-out connection. |
| `LastSeen` | Latest observed fan-out connection. |

**Reading this output:** Read `DestSpread`, `Devices`, `Rarity`, and `Dests` first. Normal browsers legitimately fan out to many sites, so browser b-sections are already suppressed; a remaining rare non-browser JA4 with many destinations is suspicious for rotation, DGA, or proxy hopping. There is no separate `Why` column, so the `Verdict` and `DestSpread` number are the evidence summary.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - rare JA4 rotating across many destinations (C2 infra rotation / DGA)` | `DestSpread >= 25` after public-only, non-browser, and rarity filters. | One rare JA4 is reaching a very large number of public IPs or SNIs. | Escalate unless a sanctioned application owner explains the pattern; block or monitor destinations per policy. |
| `MEDIUM - rare JA4 spread across multiple destinations` | `DestSpread >= 8` and `< 25` after the same filters. | The destination count is too broad for many implants or tools, but less extreme than the High band. | Validate the application and destinations; escalate if unknown, newly seen, or paired with suspicious process behavior. |

**Tunables:** `lookback = 30d` → history window; `minRarity = 0.7` → rare JA4 cutoff; `browserBsec` → suppresses Chromium/Firefox/browser-like b-sections; `DestSpread >= 8` → minimum row threshold; `DestSpread >= 25` → High threshold; `make_set` limits (`Dests` 12, `ServerJA4S` 5) → sample size shown, not detection limit.
**False positives:** Legitimate non-browser agent contacting many SaaS/CDN endpoints → browser b-section suppression does not remove all enterprise agents → verify app owner, signer, and destination list. Proxy/VPN/security client → public fan-out can be expected → confirm approved software and policy. Update clients using rotating CDN addresses → `Dests` and `ServerJA4S` help identify vendor/CDN → check change/deployment timing.
**Example row:** "`Verdict=HIGH - rare JA4 rotating across many destinations (C2 infra rotation / DGA)`; `DestSpread=31`; `DistinctIPs=31`; `DistinctSNIs=4`; `Devices=1`; `Rarity=0.96` → High because one rare non-browser JA4 contacted at least 25 distinct destinations."
**Next step:** Pivot on `JA4` and affected devices, then review process attribution, DNS history, and destination reputation. Escalate when no approved application owns the JA4 or the destination set looks generated, disposable, or infrastructure-like.

### 08 Rare destination <- many rare JA4   (Hunt · `wb_fanin.kql`)
**What it detects:** One public destination IP receiving many distinct rare non-browser JA4 fingerprints from a small number of devices.
**Hunt hypothesis:** "A redirector, staging node, or shared C2 listener shows up as one public RemoteIP aggregating many rare client JA4s from few endpoints in `DeviceNetworkEvents`."
**MITRE ATT&CK:** T1090 (Proxy) · T1071.001 (Web Protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `RemoteIP`, `DeviceId`; rarity-gated: yes (`minRarity = 0.7`); known-bad: n/a
**How it works:** The query keeps public TLS events and removes browser b-sections before computing rare JA4s. It groups by destination `RemoteIP`, then counts how many distinct rare JA4s hit that same IP. It keeps destinations with `RareJA4s >= 4` and `Devices <= 10`, which favors campaign/staging concentration over broad CDN traffic.

**Sample query (excerpt):** the detection heart of `wb_fanin.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let rare = perJa4
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(Devs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R;
ssl
| lookup kind=inner rare on ja4_
| summarize RareJA4s = dcount(ja4_, 4), Devices = dcount(DeviceId, 4), Conns = count(),
            Fingerprints = make_set(ja4_, 12), ServerJA4S = make_set(ja4s_, 5), SNIs = make_set(sni, 6),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), MaxR = max(R)
        by RemoteIP
| where RareJA4s >= 4 and Devices <= 10                 // many distinct rare fingerprints, concentrated on few hosts (campaign, not fleet-wide CDN)
| extend Verdict = case(RareJA4s >= 10, "HIGH - one destination receiving many rare fingerprints (redirector / shared C2)",
                        "MEDIUM - destination aggregating multiple rare fingerprints (staging candidate; verify it is not a shared CDN)")
| project Verdict, RemoteIP, RareJA4s, Devices, Conns, Rarity = round(MaxR, 2), Fingerprints, ServerJA4S, SNIs, FirstSeen, LastSeen
| sort by RareJA4s desc, Rarity desc
| take 200
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | `HIGH` when one destination receives at least 10 rare JA4s; `MEDIUM` when it receives 4 to 9 rare JA4s and should be checked for CDN/shared-service explanations. |
| `RemoteIP` | Public destination IP receiving the rare JA4 traffic. This panel is destination-keyed. |
| `RareJA4s` | Approximate count of distinct rare client JA4 fingerprints that connected to `RemoteIP`. This is the main fan-in number. |
| `Devices` | Approximate count of distinct endpoints that connected to the destination. Must be 10 or fewer. |
| `Conns` | Number of inspected TLS connections to the destination from the rare JA4s. |
| `Rarity` | Rounded maximum rarity score among the grouped rare JA4s. Closer to `1.00` means at least one fingerprint is extremely uncommon. |
| `Fingerprints` | Up to 12 sampled rare JA4 fingerprints that hit the destination. |
| `ServerJA4S` | Up to 5 sampled server JA4S values returned by the destination. |
| `SNIs` | Up to 6 sampled SNI names seen for the destination IP. Use these to identify CDN, hosting, or C2 names. |
| `FirstSeen` | Earliest observed connection to this destination in the grouped set. |
| `LastSeen` | Latest observed connection to this destination in the grouped set. |

**Reading this output:** Read `RemoteIP`, `RareJA4s`, `Devices`, and `SNIs` first. Normal shared corporate egress is not the key here because the panel groups on the remote destination IP; the suspicious shape is many rare non-browser JA4s concentrating on one public IP from few devices. There is no `Why` column, so the `Verdict`, `RareJA4s`, and `Devices` columns explain the evidence.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - one destination receiving many rare fingerprints (redirector / shared C2)` | `RareJA4s >= 10` and `Devices <= 10` after public-only, non-browser, and rarity filters. | A single public IP is receiving a large variety of rare client TLS fingerprints from a concentrated device set. | Escalate unless the IP is a confirmed approved shared service/CDN endpoint for those devices. |
| `MEDIUM - destination aggregating multiple rare fingerprints (staging candidate; verify it is not a shared CDN)` | `RareJA4s >= 4` and `< 10`, with `Devices <= 10`, after the same filters. | The destination may be staging, redirector, or shared infrastructure, but a CDN/shared-service explanation is still plausible. | Validate hosting/CDN ownership, SNI names, and process context before escalating. |

**Tunables:** `lookback = 30d` → observation window; `minRarity = 0.7` → rare JA4 cutoff; `browserBsec` → suppresses browser-like fingerprints; `RareJA4s >= 4` → minimum row threshold; `RareJA4s >= 10` → High threshold; `Devices <= 10` → concentration requirement; `make_set` limits (`Fingerprints` 12, `SNIs` 6, `ServerJA4S` 5) → samples displayed.
**False positives:** Shared CDN or SaaS endpoint → explicit Medium verdict tells the analyst to verify CDN/shared-service status → check `SNIs`, ASN/hosting, and vendor ownership. Security gateway or proxy service → may receive varied client fingerprints → confirm approved endpoint and device scope. Small lab or scanner hitting one IP with many clients → `Devices <= 10` can include lab concentration → verify test records and scanner owner.
**Example row:** "`Verdict=MEDIUM - destination aggregating multiple rare fingerprints (staging candidate; verify it is not a shared CDN)`; `RemoteIP=203.0.113.10`; `RareJA4s=5`; `Devices=2`; `Rarity=0.91` → Medium because the destination receives at least 4 but fewer than 10 rare non-browser JA4s from 10 or fewer devices."
**Next step:** Enrich `RemoteIP` and `SNIs` with ownership, reputation, passive DNS, and internal asset notes. Escalate when the IP is unknown/untrusted, the device set is suspicious, or process attribution points to LOLBIN/user-path binaries.

### 09 Non-standard TLS curve   (Hunt · `wb_curve.kql`)
**What it detects:** Rare public JA4 fingerprints that negotiated any TLS curve other than `x25519`, `secp256r1`, or `secp384r1`.
**Hunt hypothesis:** "A handcrafted or stripped malware TLS stack shows up as a rare JA4 negotiating a non-standard named group in the `AdditionalFields.curve` telemetry."
**MITRE ATT&CK:** T1573 (Encrypted Channel) · T1071.001 (Web Protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `AdditionalFields.curve`, `RemoteIP`, `DeviceId`; rarity-gated: yes (`minRarity = 0.7`); known-bad: n/a
**How it works:** The query keeps public TLS events with a JA4, computes tenant-wide JA4 rarity, and keeps JA4s with `R >= 0.7`. It then requires a non-empty `curve` field and filters out only the three standard production TLS 1.3 groups: `x25519`, `secp256r1`, and `secp384r1` (case variants included). Any remaining curve is treated as a custom or handcrafted TLS-stack signal.

**Sample query (excerpt):** the detection heart of `wb_curve.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let rare = perJa4
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(Devs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R;
ssl
| where isnotempty(curve) and not(curve in (stdCurves))   // anything other than the three standard TLS1.3 groups
| lookup kind=inner rare on ja4_
| summarize Devices = dcount(DeviceId, 4), Conns = count(), Curves = make_set(curve, 6),
            Dests = make_set(coalesce(sni, tostring(RemoteIP)), 8), ServerJA4S = make_set(ja4s_, 5),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), R = max(R)
        by ja4_
| extend Verdict = "HIGH - rare JA4 negotiating a non-standard TLS curve (custom / handcrafted TLS stack)"
| project Verdict, JA4 = ja4_, Curves, Devices, Conns, Rarity = round(R, 2), ServerJA4S, Dests, FirstSeen, LastSeen
| sort by Rarity desc, Conns desc
| take 200
```
**Output columns** —

| Column | What it means |
|---|---|
| `Verdict` | Always `HIGH - rare JA4 negotiating a non-standard TLS curve (custom / handcrafted TLS stack)` for rows that pass the filters. |
| `JA4` | Rare client JA4 fingerprint that negotiated the non-standard curve. |
| `Curves` | Up to 6 non-standard curve names observed, such as legacy, brainpool, sect, or ffdhe-style named groups if present in telemetry. The query does not require a specific curve name; it flags anything outside the standard list. |
| `Devices` | Approximate distinct endpoint count using the JA4 with the non-standard curve. |
| `Conns` | Number of inspected TLS connections with the non-standard curve. |
| `Rarity` | Rounded rarity score for the JA4. `0.70` is the minimum shown; closer to `1.00` means more unusual in the tenant. |
| `ServerJA4S` | Up to 5 sampled server JA4S fingerprints reached by this JA4. |
| `Dests` | Up to 8 sampled SNI names or remote IPs. |
| `FirstSeen` | Earliest matching event in the lookback. |
| `LastSeen` | Latest matching event in the lookback. |

**Reading this output:** Read `Curves`, `Rarity`, and `Dests` first. Normal production TLS 1.3 commonly negotiates `x25519`, `secp256r1`, or `secp384r1`, and those values are already suppressed; any row means a rare JA4 used a different curve. There is no separate `Why` column, so the fixed `Verdict` text and the `Curves` value explain the evidence.
**Verdict / severity bands** —

| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - rare JA4 negotiating a non-standard TLS curve (custom / handcrafted TLS stack)` | Destination is public, `curve` is non-empty, `curve` is not one of `x25519`, `secp256r1`, `secp384r1` or listed case variants, and JA4 rarity `R >= 0.7`. | A rare client TLS fingerprint negotiated a curve outside the standard production TLS 1.3 set, consistent with custom, legacy, or stripped TLS code. | Investigate the process and destination; escalate if the application is not an approved legacy/embedded client or scanner. |

**Tunables:** `lookback = 30d` → search horizon; `minRarity = 0.7` → rare JA4 cutoff; `stdCurves` → allowlist of standard curve names and case variants; `take 200` → workbook display cap. Raising `minRarity` reduces volume; adding a legitimate enterprise legacy curve to `stdCurves` suppresses that class.
**False positives:** Legacy or embedded client using older/non-standard curves → standard-curve allowlist intentionally does not suppress it → verify asset owner, software version, and business need. Compliance scanners or TLS test tools → rarity gate can still flag controlled testing → check scanner schedules and source hosts. Specialized vendor agents → public-only and rarity filters reduce noise but do not prove maliciousness → confirm signer and destination ownership.
**Example row:** "`Verdict=HIGH - rare JA4 negotiating a non-standard TLS curve (custom / handcrafted TLS stack)`; `Curves=[brainpoolP256r1]`; `Devices=1`; `Rarity=0.98`; `Dests=[203.0.113.50]` → High because the curve is not `x25519`, `secp256r1`, or `secp384r1`, and the JA4 passed the rarity gate."
**Next step:** Pivot from `JA4` and `Dests` to process attribution and software inventory. Escalate when the process is unapproved, unsigned, newly installed, user-path, or contacting an unknown public destination.

### 01 Incident-to-clean-host JA4 bridge   (Corroboration · `wb_bridge.kql`)
**What it detects:** The same rare, non-browser JA4+JA4S pair on an alerted host and on a host with no Defender alert, suggesting possible undetected spread.

**Hunt hypothesis:** "An implant or operator tool that triggered an alert on one host also shows up as the same rare TLS fingerprint on another host where alerting did not fire."

**MITRE ATT&CK:** T1071.001 (Application layer protocol: web protocols)

**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, public `RemoteIP`, `AdditionalFields.ja4`) — `DeviceId`, `TimeGenerated`, `RemoteIP`, `ja4_`, `ja4s_`, `server_name`; rarity-gated: yes (`R >= minRarity`, `PairDevs >= 2`, browser b-section suppressed); second source: `AlertEvidence` (`EntityType == "Machine"`) plus `DeviceInfo` host/IP/OS enrichment.

**How it works:** The query calculates tenant-relative rarity for each JA4+JA4S pair over the 30-day lookback, keeps rare pairs seen on at least two devices, and drops known browser b-sections. It marks devices with `AlertEvidence` as "dirty" and devices without matching alert evidence as "clean," then joins dirty-to-clean devices that share the same rare pair. The clean host's first sighting must be no earlier than one day before the dirty host's first sighting, and same-public-IP matches are suppressed as likely NAT/VPN overlap; if `AlertEvidence` is missing, the bridge has no alerted side and returns no rows.

**Sample query (excerpt):** the detection heart of `wb_bridge.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let rare = pairAgg
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(PairDevs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(PairConns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity and PairDevs >= 2 and not(substring(ja4_, 11, 12) in (browserBsec))   // tenant-relative rarity (not a raw device count) + non-browser tool/implant
// …
dirty
| join kind=inner clean on ja4_, ja4s_
| where CleanFirst >= DirtyFirst - 1d
| join kind=leftouter (meta | project DirtyDevice = DeviceId, DirtyName = DeviceName, DirtyIP = PublicIP, DirtyOS = OSPlatform) on DirtyDevice
| join kind=leftouter (meta | project CleanDevice = DeviceId, CleanName = DeviceName, CleanIP = PublicIP, CleanOS = OSPlatform) on CleanDevice
| extend SamePublicIP = (isnotempty(DirtyIP) and DirtyIP == CleanIP)
| where not(SamePublicIP)                       // same egress IP = likely same NAT/VPN, suppress
| extend Verdict = "HIGH - rare JA4 bridges an alerted host to a clean host (possible undetected spread)"
| project Verdict, ClientJA4 = ja4_, ServerJA4S = ja4s_, AlertedHost = coalesce(DirtyName, DirtyDevice), CleanHost = coalesce(CleanName, CleanDevice),
          Alerts, AlertFirst, CleanFirst, CleanSNIs, DirtyOS, CleanOS
| sort by CleanFirst asc
| take 200
```

**Output columns**

| Column | What it means |
|---|---|
| `Verdict` | Plain-English high verdict for a rare JA4 bridge from an alerted host to a clean host. |
| `ClientJA4` | Client TLS JA4 fingerprint shared by the alerted and clean hosts. |
| `ServerJA4S` | Server-side JA4S fingerprint paired with the client JA4. |
| `AlertedHost` | Device name or ID of the host that had Defender alert evidence. |
| `CleanHost` | Device name or ID of the host that had the same rare pair but no alert evidence. |
| `Alerts` | Up to five alert titles seen on the alerted host. |
| `AlertFirst` | First alert-evidence time for the alerted host. |
| `CleanFirst` | First time the clean host used the shared rare JA4+JA4S pair. |
| `CleanSNIs` | Up to five server names contacted by the clean host with that pair. |
| `DirtyOS` | Latest known OS platform for the alerted host. |
| `CleanOS` | Latest known OS platform for the clean host. |

**Reading this output:** Read `AlertedHost`, `CleanHost`, `Alerts`, and `CleanSNIs` first. A normal environment should have no rows, or rows suppressed because both devices share the same public IP. Suspicious rows show the same rare pair on a clean host, especially when the OS, host role, or destinations differ; this panel does not project a `Why` column, so `Verdict`, `Alerts`, and `CleanSNIs` carry the reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| High | `R >= minRarity`, pair seen on at least two devices, one device has alert evidence, one device does not, and public IPs differ | Possible undetected spread of the same tool or implant to a host missed by alerts | Escalate if the clean host is not clearly related to the alerted host or the destinations are not expected. |

**Tunables:** `lookback` → wider history finds older bridges but costs more; `minRarity` → higher values keep only rarer pairs; `browserBsec` → controls which browser-like JA4 b-sections are suppressed; `PairDevs >= 2` → requires the bridge to involve more than one device; same-public-IP suppression → reduces NAT/VPN false positives; `take 200` → caps returned rows.

**False positives:** Shared NAT/VPN egress → same `PublicIP` matches are suppressed → check whether the remaining hosts still share a location, jump host, or security appliance. Fleet management or security tools using the same non-browser TLS stack → browser b-sections are suppressed but other tools can remain → verify the JA4 pair against approved EDR, scanner, backup, or admin tooling.

**Example row:** "`AlertedHost=FIN-07`, `CleanHost=ENG-22`, `Alerts=['Suspicious PowerShell']`, `CleanSNIs=['api.example']` → High because a clean host shares the same rare JA4+JA4S pair as an alerted host without the same public-IP suppression."

**Next step:** Open both device timelines, compare process/network activity around `CleanFirst` and `AlertFirst`, and isolate or escalate the clean host if no approved shared tool explains the fingerprint.

### 02 Mark-of-the-Web to first C2 callout   (Corroboration · `wb_motw.kql`)
**What it detects:** A web-downloaded file that later runs and makes a rare or structurally suspicious TLS callout to a public, non-Microsoft destination within 24 hours.

**Hunt hypothesis:** "A phished or drive-by-delivered payload shows up as a Mark-of-the-Web file creation followed by a rare or odd TLS first C2 callout in endpoint and network telemetry."

**MITRE ATT&CK:** T1204.002 (Malicious file) · T1071.001 (Web protocols) · T1566.001 (Spearphishing attachment)

**Reads:** `DeviceFileEvents` (`FileCreated`, `FileOriginUrl` populated, `SHA1` populated) — download time, file path, hash, origin/referrer; `DeviceNetworkEvents` (`SslConnectionInspected` and `ConnectionSuccess`) — JA4/JA4S, SNI, cert issuer/subject, remote flow key, initiating process/hash/signer/parent; rarity-gated: yes, or structurally gated by no-SNI/no-ALPN/self-signed/legacy TLS; second source: `DeviceFileEvents`.

**How it works:** The query treats `DeviceFileEvents.FileCreated` with `FileOriginUrl` and `SHA1` as the Mark-of-the-Web download signal. It links that downloaded file to a network process by SHA1-exact match or filename match, then joins the process to a rare or structurally suspicious TLS flow on the same device and remote flow key. The TLS callout must occur after the download and within `calloutWindow` (24 hours); if `DeviceFileEvents` or origin URL/hash data is missing, this panel returns no rows.

**Sample query (excerpt):** the detection heart of `wb_motw.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| extend SuspicionScore =
      iff(selfSig,    25, 0)
    + iff(noSNI,      20, 0)
    + iff(legacyTLS,  20, 0)
    + iff(noALPN,     12, 0)
    + iff(MatchType == "SHA1-exact", 10, 5)                    // stronger correlation = bonus
    + iff(MinutesSinceDownload < 30,  20,                      // rapid first callout (<30 min)
      iff(MinutesSinceDownload < 240, 10, 0))                  // called out within 4 h
    + iff(isempty(Signer), 15, 0)                              // unsigned calling process
// …
| project
    DeviceName, DownloadTime, FileName, DownloadFolder, FileSHA1,
    FileOriginUrl, FileOriginReferrerUrl,
    Proc, ProcFolder, Signer, Parent, MatchType,
    FirstCallout, MinutesSinceDownload, CalloutCount,
    RemoteIP, sni, ja4_, ja4s_, issuer,
    Rarity, SuspicionScore, Why
| sort by SuspicionScore desc, MinutesSinceDownload asc, DownloadTime desc
```

**Output columns**

| Column | What it means |
|---|---|
| `DeviceName` | Device where the web download and TLS callout occurred. |
| `DownloadTime` | First observed time the file was created from the web. |
| `FileName` | Downloaded file name. |
| `DownloadFolder` | Folder path where the file was written. |
| `FileSHA1` | SHA1 hash recorded for the downloaded file. |
| `FileOriginUrl` | URL that supplied the downloaded file. |
| `FileOriginReferrerUrl` | Referrer URL, when present. |
| `Proc` | Process name that made the network callout. |
| `ProcFolder` | Folder path for the calling process. |
| `Signer` | Process signer/company from connection telemetry; blank means unsigned or unavailable. |
| `Parent` | Parent process name from connection telemetry. |
| `MatchType` | `SHA1-exact` is strongest; `filename` is weaker and can match common names. |
| `FirstCallout` | First TLS callout time after the download. |
| `MinutesSinceDownload` | Minutes between download and first callout. |
| `CalloutCount` | Number of matching callouts in the window. |
| `RemoteIP` | Public remote IP contacted by the process. |
| `sni` | Server name from TLS metadata, when present. |
| `ja4_` | Client JA4 fingerprint used by the process. |
| `ja4s_` | Server JA4S fingerprint paired with the JA4. |
| `issuer` | Certificate issuer from TLS metadata. |
| `Rarity` | Tenant-relative rarity score for the JA4+JA4S pair. |
| `SuspicionScore` | Additive score from structural JA4 flags, match strength, callout speed, and unsigned status. |
| `Why` | Plain-English evidence list: structural flags, download-to-callout gap, match type, and signer. |

**Reading this output:** Read `SuspicionScore`, `MinutesSinceDownload`, `MatchType`, and `Why` first. Normal web installers usually have a known signer, a clear origin URL, and either a weaker filename-only match or a less suspicious JA4 shape. Suspicious rows call out quickly, use `SHA1-exact`, are unsigned, or show no-SNI, no-ALPN, self-signed, or legacy-TLS indicators; the `Why` column carries that reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| Critical | `SuspicionScore >= 80` | Strong download-to-C2 chain with multiple structural or process-risk adders | Escalate to Tier-2/IR and preserve the file/hash. |
| High | `SuspicionScore >= 50` | Credible Mark-of-the-Web payload followed by a rare or suspicious callout | Triage the file, process tree, hash reputation, and destination. |
| Medium | `SuspicionScore >= 30` | Some suspicious evidence but fewer adders or weaker correlation | Validate signer, origin URL, and whether the file is expected. |
| Low | `< 30` | Weakest in-window chain | Document or suppress if explained by approved software. |

**Tunables:** `lookback` → search horizon; `minRarity` → higher values reduce rare-pair matches; `calloutWindow` → wider window catches slower callbacks but increases false positives; `msSni` → suppresses Microsoft destinations; structural gates (`noSNI`, `noALPN`, `selfSig`, `legacyTLS`) → let odd implants appear before rarity is established.

**False positives:** Common installer names such as `setup.exe` → `MatchType` exposes filename-only correlation and `SHA1-exact` receives the stronger score → require hash/process validation before escalation. Legitimate web-delivered tools → process signer and origin/referrer are shown → confirm the signer, download source, and change ticket.

**Example row:** "`FileName=invoice.exe`, `MatchType=SHA1-exact`, `MinutesSinceDownload=7.4`, `Why=['self-signed cert','no-SNI to public dest','MOTW download → callout in 7.4 min','unsigned process']` → Critical because a fresh web file rapidly made an unsigned, structurally suspicious TLS callout."

**Next step:** Collect the file hash and process tree, check whether the user expected the download, and escalate immediately if the file is unknown, unsigned, or tied to a phishing case.

### 03 Detonation and alert corroboration   (Corroboration · `wb_detonation.kql`)
**What it detects:** A rare JA4 TLS callout on a device that also has an ASR event or Defender alert within 30 minutes.

**Hunt hypothesis:** "Exploit, script, or malware execution shows up as a rare TLS callout plus endpoint detonation or alert evidence close in time on the same device."

**MITRE ATT&CK:** T1071.001 (Web protocols) · T1203 (Exploitation for client execution) · T1059 (Command and scripting interpreter)

**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, public non-Microsoft destination, `AdditionalFields.ja4`) — device, destination, JA4/JA4S, SNI, cert issuer/subject; `DeviceEvents` (`ActionType startswith "Asr"`) — ASR action/process/file; `AlertEvidence` (device evidence) — alert title and severity; rarity-gated: yes; second source: `DeviceEvents` and `AlertEvidence`.

**How it works:** The query calculates IDF-style rarity for JA4+JA4S pairs and keeps rare public, non-Microsoft TLS connections. It joins each rare TLS connection to ASR events and Defender alert evidence on the same `DeviceId` where the timestamps fall within `detWindow` (±30 minutes). Each row is scored as `round(Rarity * 100)` plus ASR bonus and alert-severity weight; if both ASR/alert sources are missing, this panel returns no rows.

**Sample query (excerpt):** the detection heart of `wb_detonation.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| extend SevWeight = case(AlertSeverity == "High",   30,
                          AlertSeverity == "Medium",  20,
                          AlertSeverity == "Low",     10, 0)
| extend IncidentScore = toint(round(100.0 * Rarity))
                       + iff(CorrobType == "ASR event", 20, 0)
                       + SevWeight
| extend Why = strcat(
    "Rare JA4 (R=", tostring(Rarity), ") → ",
    coalesce(sni, RemoteIP), " | ",
    CorrobType, ": '", CorrobDetail, "'",
    " within ", tostring(MinAbsGapMin), " min",
    iff(selfSig, " | self-signed cert", ""),
    iff(isnotempty(AlertSeverity), strcat(" [sev=", AlertSeverity, "]"), ""))
| project
    DeviceName, FirstSslTime, ja4_, ja4s_, sni, issuer, RemoteIP, Rarity,
    CorrobType, CorrobDetail, CorrobContext, AlertTitle, AlertSeverity,
    MinAbsGapMin, IncidentScore, Why
| sort by IncidentScore desc, MinAbsGapMin asc
```

**Output columns**

| Column | What it means |
|---|---|
| `DeviceName` | Device with both rare TLS and detonation/alert evidence. |
| `FirstSslTime` | First matching rare TLS time in the summarized row. |
| `ja4_` | Client JA4 fingerprint. |
| `ja4s_` | Server JA4S fingerprint. |
| `sni` | TLS server name, when present. |
| `issuer` | Certificate issuer from TLS metadata. |
| `RemoteIP` | Public destination IP. |
| `Rarity` | Tenant-relative rarity score for the JA4+JA4S pair. |
| `CorrobType` | Corroboration source: `ASR event` or `Defender alert`. |
| `CorrobDetail` | ASR action name or alert title. |
| `CorrobContext` | ASR initiating process for ASR rows. |
| `AlertTitle` | Defender alert title for alert rows. |
| `AlertSeverity` | Defender alert severity, when present. |
| `MinAbsGapMin` | Smallest absolute time gap in minutes between rare TLS and the corroborating signal. |
| `IncidentScore` | Rarity score plus ASR and alert-severity bonuses; practical range is 0-150. |
| `Why` | Plain-English reasoning: rarity, destination, corroboration type/detail, time gap, self-signed flag, and alert severity. |

**Reading this output:** Read `IncidentScore`, `CorrobType`, `CorrobDetail`, `MinAbsGapMin`, and `Why` first. Normal noise is reduced by requiring a rare public non-Microsoft JA4 and a ±30 minute endpoint signal. Suspicious rows have a small time gap, a high-severity alert or ASR block/action, and a rare or self-signed destination; the `Why` column carries the reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| Highest priority | `IncidentScore >= 120` | Very rare JA4 plus strong ASR or medium/high alert evidence | Escalate and review the full incident/device timeline. |
| High | `IncidentScore 90-119` | Rare JA4 with ASR or alert corroboration in the 30-minute window | Triage alert details, process context, and destination. |
| Review | `IncidentScore 70-89` | Rarity-gated row with weaker severity weight or lower rarity | Validate whether ASR was audit-only and whether the alert is related. |

**Tunables:** `lookback` → historical range; `minRarity` → rarity cutoff; `detWindow` → allowed rare-TLS-to-detonation gap; `msSni` → Microsoft destination suppression; optional ASR filter `ActionType endswith "Block"` → reduces audit-mode ASR noise.

**False positives:** ASR audit-mode events → code comments recommend adding `endswith "Block"` in audit-heavy tenants → check whether the action blocked or only audited. Unrelated endpoint alert near rare traffic → ±30-minute window and same-device join reduce noise → inspect `CorrobDetail`, `AlertTitle`, process context, and `MinAbsGapMin`.

**Example row:** "`DeviceName=WS-14`, `CorrobType=Defender alert`, `AlertSeverity=High`, `Rarity=0.92`, `MinAbsGapMin=3.1`, `Why='Rare JA4 (R=0.92) → host.example | Defender alert: Suspicious script within 3.1 min [sev=High]'` → Highest priority because rare TLS and high-severity alert evidence are tightly coupled."

**Next step:** Open the Defender incident or ASR event, confirm the process that made the TLS connection, and escalate when the corroboration detail matches exploit, script, or malware behavior.

### 04 Suspicious process lineage   (Corroboration · `wb_lineage.kql`)
**What it detects:** A rare JA4 callout whose attributed process has suspicious parentage, signer, or path provenance.

**Hunt hypothesis:** "A phish, script host, drive-by, or unsigned user-path implant shows up as a rare TLS callout from a process with suspicious lineage in endpoint process telemetry."

**MITRE ATT&CK:** T1059 (Command and scripting interpreter) · T1204 (User execution) · T1566 (Phishing)

**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected` for JA4 rarity and `ConnectionSuccess` for process attribution) — device, flow key, initiating process/hash/signer/parent/path; `DeviceProcessEvents` (latest event per `DeviceId`, process name) — signer, folder, parent/grandparent, command line, SHA1; rarity-gated: yes; second source: `DeviceProcessEvents` with `ConnectionSuccess` as the required process-attribution join.

**How it works:** The query finds rare public, non-Microsoft JA4+JA4S pairs, then attributes rare connections to processes by `DeviceId`, `RemoteIP`, and `RemotePort` using `ConnectionSuccess`. It enriches each process with the most recent `DeviceProcessEvents` record in the lookback and flags Office parents, script-host parents, browser-parent-to-non-browser-child, and unsigned user/temp/download path execution. There is no narrow ± time window beyond the 30-day lookback; if `ConnectionSuccess` process attribution is missing, the panel cannot link rare JA4 to a process, while missing `DeviceProcessEvents` leaves DPE-only fields blank and uses connection telemetry fallback.

**Sample query (excerpt):** the detection heart of `wb_lineage.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| extend Severity = case(
    officeSpawn or browserToNonBrowser, "High",   // document/browser spawning a non-browser network child
    unsigned and isUserPath,            "High",   // unsigned binary in a user-writable path
    scriptSpawn,                        "Medium", // script host as spawning parent
                                        "Medium")
| extend SuspicionScore =
      iff(officeSpawn,          40, 0)
    + iff(browserToNonBrowser,  35, 0)
    + iff(scriptSpawn,          25, 0)
    + iff(unsigned,             20, 0)
    + iff(isUserPath,           15, 0)
// …
| project
    Severity, SuspicionScore,
    Proc, FinalParent, DPE_GParent, FinalSigner, FinalFolder, DPE_CmdLine,
    ja4_, ja4s_, sni, issuer, Dests,
    DeviceName, Rarity, Conns, LastSeen, Why
| sort by SuspicionScore desc, Rarity desc, Conns asc
```

**Output columns**

| Column | What it means |
|---|---|
| `Severity` | `High` or `Medium` based on lineage flags. |
| `SuspicionScore` | Additive score from Office/browser/script parent, unsigned status, user path, and rarity bonus. |
| `Proc` | Network-calling process name. |
| `FinalParent` | Best available direct parent process, preferring DPE over connection telemetry. |
| `DPE_GParent` | Grandparent process from `DeviceProcessEvents`, when present. |
| `FinalSigner` | Best available signer/company value. Blank means unsigned or unavailable. |
| `FinalFolder` | Best available process folder path. |
| `DPE_CmdLine` | Command line from `DeviceProcessEvents`, when present. |
| `ja4_` | Client JA4 fingerprint. |
| `ja4s_` | Server JA4S fingerprint. |
| `sni` | TLS server name, when present. |
| `issuer` | Certificate issuer. |
| `Dests` | Up to six contacted destinations for the process/JA4 pair. |
| `DeviceName` | Device where the process ran. |
| `Rarity` | Tenant-relative rarity score for the JA4+JA4S pair. |
| `Conns` | Count of rare connections for this process/JA4 pair. |
| `LastSeen` | Last observed rare TLS time for the row. |
| `Why` | Plain-English array of lineage reasons such as Office parent, script-host parent, unsigned process, or user/temp path. |

**Reading this output:** Read `Severity`, `Proc`, `FinalParent`, `FinalFolder`, `FinalSigner`, and `Why` first. Normal signed browser traffic is suppressed, including mainstream signed browser children. Suspicious rows show Office spawning a network child, browser spawning a non-browser child, script-host ancestry, or an unsigned process from a user-writable path; the `Why` column carries those lineage reasons.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| High | Office parent, browser-to-non-browser child, or unsigned process in user path | Strong phish, drive-by, or dropped-implant lineage around a rare JA4 | Escalate if the process is not an approved tool. |
| Medium | Script-host parent or user-path provenance that passes the gate | Suspicious but more commonly admin/script related | Validate command line, signer, and user activity. |

**Tunables:** `lookback` → source history; `minRarity` → rare JA4 cutoff; `officeParents`, `browserParents`, `scriptParents` → parent process classes; `userPathFrags` → user-writable path detection; `msSni` → Microsoft destination suppression.

**False positives:** IT automation scripts → script-host parent is only Medium and rare JA4 is required → check `DPE_CmdLine`, change records, and destination. Browser helper processes → signed mainstream browser processes are suppressed and browser parent is suspicious only when it spawns a non-browser child → verify `Proc`, signer, and parent chain.

**Example row:** "`Severity=High`, `Proc=updater.exe`, `FinalParent=winword.exe`, `FinalFolder=C:\Users\...\AppData\...`, `Why=['Office parent: winword.exe','unsigned process','user/temp path: ...']` → High because Office spawned an unsigned user-path process that made a rare JA4 callout."

**Next step:** Pull the process tree and command line, collect the binary hash, and escalate when Office/script/browser lineage cannot be tied to approved software.

### 05 AiTM session-theft corroboration   (Corroboration · `wb_aitm.kql`)
**What it detects:** A risky Entra sign-in for a user whose device makes a rare, non-browser, or Evilginx JA4 callout within 30 minutes.

**Hunt hypothesis:** "AiTM or OAuth-token theft shows up as a risky sign-in in identity telemetry plus a non-browser or rare TLS callout on the user's device."

**MITRE ATT&CK:** T1528 (Steal application access token) · T1550.004 (Web session cookie) · T1071.001 (Web protocols)

**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, public JA4) — device, destination, JA4/JA4S, b-section, cipher count; `DeviceLogonEvents` — device-to-account mapping by `AccountName`; `SigninLogs` (`RiskLevelDuringSignIn in ("high","medium")`) — UPN, risk, sign-in IP, location, app; rarity-gated: yes, or included when non-browser or hard-coded Evilginx JA4; second source: `SigninLogs` with `DeviceLogonEvents` mapping.

**How it works:** The query builds JA4 candidates when the fingerprint is rare, non-browser-shaped, or exactly matches the hard-coded Evilginx JA4. It maps devices to users through `DeviceLogonEvents.AccountName`, joins to risky Entra sign-ins by UPN prefix, and keeps rows within `aitm_window` (±30 minutes). The correlated risky-sign-in branch returns no rows without `SigninLogs` and device/user mapping; the query also surfaces the Evilginx JA4 as an explicit uncorroborated fallback so analysts can verify session theft even when the sign-in branch is sparse.

**Sample query (excerpt):** the detection heart of `wb_aitm.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | join kind=inner devUpn on DeviceId
    | join kind=inner risky on $left.Acct == $right.UPNPrefix
    | where abs(ConnTime - SignInTime) <= aitm_window
    | extend TimeGapMin = round(datetime_diff('second', ConnTime, SignInTime) / 60.0, 1)
    | extend IsEvilginx = (ja4_ == evilginxJa4)
    | extend Why = strcat(iff(IsEvilginx, "*** Evilginx JA4 *** ; ", ""), "risky Entra sign-in (", RiskLevel, ") for ", UPN, " + ", iff(nonBrowser, "non-browser", "rare"), " JA4 on their device within 30m; app=", AppDisplayName, "; sign-in from ", Location)
    | project Verdict = iff(IsEvilginx, "CRITICAL - Evilginx + risky sign-in", "HIGH - AiTM session-theft pattern"),
              UPN, DeviceName, RiskLevel, RiskState, ja4_, ja4s_, bsec, Rarity = round(R, 2), nonBrowser,
              SignInIP, Location, AppDisplayName, SNI = sni, SignInTime, ConnTime, TimeGapMin, Why;
// …
    | extend Verdict = "HIGH - Evilginx JA4 (uncorroborated; verify session theft)",
             UPN = "(unattributed)", RiskLevel = "", RiskState = "", SignInIP = "", Location = "", AppDisplayName = "",
             SignInTime = datetime(null), TimeGapMin = real(null),
             Why = strcat("*** Evilginx AiTM JA4 *** on device with no corroborating risky Entra sign-in in window; ", Conns, " callout(s) - verify token theft")
    | project Verdict, UPN, DeviceName, RiskLevel, RiskState, ja4_, ja4s_, bsec, Rarity = round(R, 2), nonBrowser,
              SignInIP, Location, AppDisplayName, SNI = sni, SignInTime, ConnTime, TimeGapMin, Why;
union correlated, evilginxUncorr
| sort by Verdict asc, TimeGapMin asc
```

**Output columns**

| Column | What it means |
|---|---|
| `Verdict` | Critical/High text describing Evilginx, AiTM session-theft pattern, or uncorroborated Evilginx. |
| `UPN` | User principal name tied to the risky sign-in; `(unattributed)` for uncorroborated Evilginx. |
| `DeviceName` | Device that made the JA4 callout. |
| `RiskLevel` | Entra sign-in risk level (`high` or `medium`) for correlated rows. |
| `RiskState` | Entra risk state from `SigninLogs`. |
| `ja4_` | Client JA4 fingerprint. |
| `ja4s_` | Server JA4S fingerprint. |
| `bsec` | JA4 b-section used to distinguish browser-like from non-browser-like stacks. |
| `Rarity` | Tenant-relative rarity score, or 0 when included only by non-browser/Evilginx logic. |
| `nonBrowser` | True when JA4 shape is not browser-like by b-section/cipher-count logic. |
| `SignInIP` | IP address used in the risky sign-in. |
| `Location` | Sign-in location from Entra. |
| `AppDisplayName` | Application involved in the risky sign-in. |
| `SNI` | TLS server name contacted by the device. |
| `SignInTime` | Risky sign-in time. |
| `ConnTime` | JA4 callout time. |
| `TimeGapMin` | Signed minute gap between callout and sign-in. |
| `Why` | Plain-English reasoning, including risky sign-in level, UPN, non-browser/rare JA4, app, location, and Evilginx marker when present. |

**Reading this output:** Read `Verdict` and `Why` first, then confirm `UPN`, `DeviceName`, `RiskLevel`, `AppDisplayName`, and `TimeGapMin`. Normal rows should be absent unless identity risk and device TLS activity align in time. Suspicious rows show a high/medium risky sign-in plus rare or non-browser JA4 on the same user's device; the `Why` column carries the reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| Critical | `ja4_ == evilginxJa4` and risky sign-in correlation exists | Known Evilginx JA4 plus identity risk | Escalate immediately for session theft containment. |
| High | Risky sign-in plus rare or non-browser JA4 within ±30 minutes | AiTM/session-theft pattern | Review sign-in, device, token, and OAuth activity. |
| High | Evilginx JA4 without risky sign-in correlation | High-signal Evilginx fallback, but uncorroborated | Verify token theft and investigate the device manually. |

**Tunables:** `lookback` → history; `minRarity` → rare cutoff; `aitm_window` → allowed sign-in/callout gap; `evilginxJa4` → hard-coded Evilginx fingerprint; `browserBsec` and cipher-count logic → browser-vs-non-browser classification.

**False positives:** Shared or multi-user devices → UPN prefix mapping through `DeviceLogonEvents.AccountName` can over-associate users → verify the user was active on the device. Risky sign-in unrelated to device traffic → ±30-minute window reduces but does not eliminate coincidence → compare `SignInIP`, `Location`, app, and device timeline.

**Example row:** "`Verdict=HIGH - AiTM session-theft pattern`, `UPN=analyst@example`, `RiskLevel=High`, `nonBrowser=true`, `TimeGapMin=6.2`, `Why='risky Entra sign-in (High) for analyst@example + non-browser JA4 on their device within 30m; app=Office 365; sign-in from ...'` → High because identity risk and device TLS behavior line up."

**Next step:** Escalate high-risk users for token/session revocation review, check impossible travel and OAuth consent, and isolate the device if the JA4 destination or process is unknown.

### 06 Cloud exfiltration corroboration   (Corroboration · `wb_cloudexfil.kql`)
**What it detects:** A rare JA4 outbound callout that occurs near a cloud upload, download, export, share, sync, or file-operation event from the same device public IP.

**Hunt hypothesis:** "Data exfiltration through cloud services shows up as rare TLS from a device plus cloud-app file activity from that same egress IP within one hour."

**MITRE ATT&CK:** T1567.002 (Exfiltration to cloud storage) · T1071.001 (Web protocols)

**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, public JA4) — device, public destination, JA4/JA4S, b-section, cipher count; `CloudAppEvents` (upload/download/export/share/sync/file-operation action or anonymous proxy) — app, account, object, IP, proxy/country; `DeviceInfo` — device `PublicIP` ownership window; `DeviceLogonEvents` — optional UPN enrichment; rarity-gated: yes; second source: `CloudAppEvents`.

**How it works:** The query builds a rare JA4 set from public TLS connections, then filters cloud-app events to exfil-style activities or anonymous-proxy rows. It joins the device's public IP from `DeviceInfo` to `CloudAppEvents.IPAddress`, verifies the device held that IP around the callout, and keeps cloud activity within `exfil_window` (±1 hour) of the rare JA4 connection. If `CloudAppEvents` or device public-IP data is missing, the corroborated panel returns no rows.

**Sample query (excerpt):** the detection heart of `wb_cloudexfil.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
rareSsl
| join kind=inner (devicePublicIP | project DeviceId, PublicIP, IpStart, IpEnd) on DeviceId
| where ConnTime between (IpStart - 1d .. IpEnd + 1d)   // device actually held this public IP around the callout (not just the latest IP)
| join kind=inner cloudExfil on $left.PublicIP == $right.IPAddress
| where abs(ExfilTime - ConnTime) <= exfil_window
| join kind=leftouter (deviceToUpn | project DeviceId, UPN) on DeviceId
| extend TimeGapMin = round(datetime_diff('second', ExfilTime, ConnTime) / 60.0, 1)
| extend Why = strcat("Rare JA4 + cloud exfil from same device (PublicIP match) +/-1h",
    iff(IsAnonymousProxy, "; *** ANONYMOUS PROXY ***", ""), "; app=", Application,
    "; activity=", coalesce(ActivityType, ActionType), "; object=", coalesce(ObjectName, ""),
    "; bsec=", bsec, " ciphers=", tostring(cipherCnt))
| project Application, ActivityType, ActionType, ObjectName, AccountDisplayName, UserPrincipalName = coalesce(UPN, ""),
          DeviceName, ja4_, ja4s_, bsec, cipherCnt, Rarity = round(R, 2), PublicIP, RemoteIP, SNI = sni,
          IsAnonymousProxy, CountryCode, ConnTime, ExfilTime, TimeGapMin, Why
| sort by IsAnonymousProxy desc, TimeGapMin asc, ExfilTime desc
```

**Output columns**

| Column | What it means |
|---|---|
| `Application` | Cloud application involved in the activity. |
| `ActivityType` | Cloud app activity type when populated. |
| `ActionType` | Cloud app action type, often used when `ActivityType` is blank. |
| `ObjectName` | File, object, or resource name involved. |
| `AccountDisplayName` | Cloud account display name. |
| `UserPrincipalName` | Device logon UPN enrichment, when available. |
| `DeviceName` | Device tied to the public IP and rare JA4. |
| `ja4_` | Client JA4 fingerprint. |
| `ja4s_` | Server JA4S fingerprint. |
| `bsec` | JA4 b-section. |
| `cipherCnt` | Cipher count parsed from JA4. |
| `Rarity` | Tenant-relative rarity score for the JA4. |
| `PublicIP` | Device public egress IP used to join to the cloud event. |
| `RemoteIP` | Rare JA4 destination IP. |
| `SNI` | TLS server name for the rare JA4 callout. |
| `IsAnonymousProxy` | True when MDCA marked the cloud activity as anonymous proxy. |
| `CountryCode` | Country code from the cloud app event. |
| `ConnTime` | Rare JA4 connection time. |
| `ExfilTime` | Cloud app event time. |
| `TimeGapMin` | Signed minutes between rare JA4 connection and cloud activity. |
| `Why` | Plain-English summary of rare JA4 plus cloud exfil activity, app, object, anonymous proxy flag, b-section, and cipher count. |

**Reading this output:** Read `IsAnonymousProxy`, `Application`, `ActivityType`/`ActionType`, `ObjectName`, `TimeGapMin`, and `Why` first. Normal Microsoft 365 apps are suppressed unless `IsAnonymousProxy` is true. Suspicious rows involve non-Microsoft cloud activity or anonymous proxy use near rare TLS from the same device egress IP; the `Why` column carries the reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| Highest priority | `IsAnonymousProxy == true` | Cloud activity used an anonymous proxy near rare JA4 traffic | Escalate and review account/session controls. |
| High | Non-Microsoft exfil-style activity within ±1 hour of rare JA4 | Possible cloud exfiltration linked to unusual TLS | Triage account, object, destination, and device. |
| Review | Same-device public-IP match with larger context uncertainty | Could be NAT/proxy overlap or legitimate cloud use | Validate IP ownership, user, and business purpose. |

**Tunables:** `lookback` → history; `minRarity` → rare JA4 cutoff; `exfil_window` → allowed cloud-event/callout gap; `exfilActivityTypes` and regex → which cloud actions count as exfil-style; Microsoft app exclusion list → suppresses routine M365 activity unless anonymous proxy is present.

**False positives:** Shared public IP/NAT → `DeviceInfo` public-IP ownership window constrains the join → confirm the device actually owned the IP at the relevant time. Legitimate non-Microsoft SaaS uploads → Microsoft apps are suppressed but other approved SaaS remains → verify `Application`, `ObjectName`, account, and business context.

**Example row:** "`IsAnonymousProxy=true`, `Application=Box`, `ActivityType=Upload`, `ObjectName=finance.zip`, `Rarity=0.88`, `TimeGapMin=4.0`, `Why='Rare JA4 + cloud exfil from same device (PublicIP match) +/-1h; *** ANONYMOUS PROXY ***; app=Box; activity=Upload; object=finance.zip; ...'` → Highest priority because anonymous-proxy cloud upload and rare TLS coincide."

**Next step:** Check the account and file activity in cloud-app logs, confirm whether the device owned `PublicIP`, and escalate if the object or proxy use is unauthorized.

### 07 Phish-to-implant chain   (Corroboration · `wb_phish.kql`)
**What it detects:** A delivered phishing or malware email followed by a rare JA4 callout from the recipient's device within two hours.

**Hunt hypothesis:** "A delivered phish that leads to implant execution shows up as email threat telemetry followed by rare TLS from a device used by the recipient."

**MITRE ATT&CK:** T1566.001 (Spearphishing attachment) · T1071.001 (Web protocols)

**Reads:** `EmailEvents` (`ThreatTypes` has `Phish` or `Malware`, `DeliveryAction != "Blocked"`) — recipient, subject, sender, detection, message ID; `DeviceLogonEvents` — recipient-prefix-to-device mapping; `DeviceNetworkEvents` (`SslConnectionInspected`, public JA4) — device, destination, JA4/JA4S, b-section, cipher count; rarity-gated: yes; second source: `EmailEvents` with `DeviceLogonEvents` mapping.

**How it works:** The query finds delivered phish/malware email, maps the recipient prefix to all devices where that account logged on, and joins those devices to rare public JA4 callouts. It only keeps callouts after the email delivery and within `phish_window` (2 hours). If `EmailEvents` or `DeviceLogonEvents` mapping is missing, the chain returns no rows.

**Sample query (excerpt):** the detection heart of `wb_phish.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let rareSet = (
    pairAgg
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(Devs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R);
// …
phishEmails
| extend RecipPrefix = tolower(tostring(split(RecipientEmailAddress, "@")[0]))
| join kind=inner (recipientDevices | project Acct, DeviceId, DeviceName) on $left.RecipPrefix == $right.Acct
| join kind=inner (rareSsl | project DeviceId, ConnTime, RemoteIP, sni, ja4_, ja4s_, bsec, cipherCnt, R) on DeviceId
| where ConnTime > EmailTime and (ConnTime - EmailTime) <= phish_window
| extend MinutesFromEmail = round(datetime_diff('second', ConnTime, EmailTime) / 60.0, 1)
| extend Why = strcat("Phish->implant chain: ", ThreatTypes, " email delivered (", SenderMailFromDomain, ") then rare JA4 callout on recipient device within 2h; detect=", DetectionMethods, "; bsec=", bsec, " ciphers=", tostring(cipherCnt))
| project RecipientEmailAddress, Subject, ThreatTypes, DetectionMethods, SenderFromAddress, SenderMailFromDomain, EmailTime,
          DeviceName, ja4_, ja4s_, bsec, cipherCnt, Rarity = round(R, 2), RemoteIP, SNI = sni, ConnTime, MinutesFromEmail, Why
| sort by MinutesFromEmail asc, EmailTime desc
```

**Output columns**

| Column | What it means |
|---|---|
| `RecipientEmailAddress` | Email recipient tied to the device mapping. |
| `Subject` | Email subject. |
| `ThreatTypes` | Email threat type, such as Phish or Malware. |
| `DetectionMethods` | Email detection method details. |
| `SenderFromAddress` | Displayed sender address. |
| `SenderMailFromDomain` | Sender mail-from domain. |
| `EmailTime` | Email delivery/event time. |
| `DeviceName` | Recipient-associated device that made the rare callout. |
| `ja4_` | Client JA4 fingerprint. |
| `ja4s_` | Server JA4S fingerprint. |
| `bsec` | JA4 b-section. |
| `cipherCnt` | Cipher count parsed from JA4. |
| `Rarity` | Tenant-relative JA4 rarity score. |
| `RemoteIP` | Rare JA4 destination IP. |
| `SNI` | TLS server name, when present. |
| `ConnTime` | Rare JA4 callout time. |
| `MinutesFromEmail` | Minutes from email time to rare callout. |
| `Why` | Plain-English chain: delivered threat email, sender domain, rare JA4 within 2 hours, detection method, b-section, and cipher count. |

**Reading this output:** Read `MinutesFromEmail`, `RecipientEmailAddress`, `Subject`, `DeviceName`, and `Why` first. Blocked email is excluded, so rows represent delivered threats. Suspicious rows have a short email-to-callout gap and a rare JA4 on a recipient device; the `Why` column carries the chain reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| Highest priority | Smallest `MinutesFromEmail`; all rows are `<= 120` minutes by query | Rare JA4 happened soon after delivered phish/malware | Escalate if user interaction or device process evidence supports execution. |
| High | Any delivered phish/malware row within the 2-hour window | Plausible phish-to-implant chain | Triage the email, recipient device, and JA4 destination. |
| Review | Multi-device recipient mapping or weak business context | Possible mapping coincidence | Confirm which device the user used and whether the email was opened/clicked. |

**Tunables:** `lookback` → historical range; `minRarity` → rare JA4 cutoff; `phish_window` → allowed time from email to callout; email filters (`ThreatTypes`, `DeliveryAction`) → scope the source to delivered phish/malware.

**False positives:** User has multiple devices → the query keeps all devices per account from `DeviceLogonEvents` → verify the active device at email time. Security tests or benign delivered samples → blocked messages are excluded but delivered simulations can remain → validate `Subject`, sender domain, detection method, and user activity.

**Example row:** "`RecipientEmailAddress=user@example`, `ThreatTypes=Phish`, `SenderMailFromDomain=lookalike.example`, `MinutesFromEmail=18.5`, `Why='Phish->implant chain: Phish email delivered (...) then rare JA4 callout on recipient device within 2h; ...'` → Highest priority because delivered phish was followed by rare TLS on the recipient's device."

**Next step:** Open the email event, check URL/attachment and user activity, then pivot to the device process tree for the JA4 callout and escalate if execution is plausible.

### 08 Ransomware staging plus rare JA4 check-in   (Corroboration · `wb_ransom.kql`)
**What it detects:** A ransomware-like burst of file operations on a host with a rare JA4 callout within 30 minutes.

**Hunt hypothesis:** "Operator C2 or malware check-in around encryption shows up as mass file rename/delete activity plus a rare TLS callout on the same host."

**MITRE ATT&CK:** T1486 (Data encrypted for impact) · T1071.001 (Web protocols)

**Reads:** `DeviceFileEvents` (`FileRenamed`, `FileModified`, `FileDeleted`, `FileCreated`, with ransomware-token prefilter and extension checks) — file operation counts, sample files, extensions; `DeviceNetworkEvents` (`SslConnectionInspected`, public JA4) — JA4/JA4S, destinations, connection time; rarity-gated: yes; second source: `DeviceFileEvents`.

**How it works:** The query bins file activity into 10-minute bursts and keeps high-volume rename/delete/create/modify patterns, especially when ransomware-like extensions appear. It calculates JA4 rarity from public TLS and joins rare callouts to file bursts on the same device within ±30 minutes. If `DeviceFileEvents` is missing or the file-operation thresholds are not met, the panel returns no rows.

**Sample query (excerpt):** the detection heart of `wb_ransom.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R;
// …
ssl
| lookup kind=inner rare on ja4_
| join kind=inner burst on DeviceId
| where ConnTime between (BurstTime - 30m .. BurstTime + 30m)
| summarize CalloutConns = count(), Dests = make_set(coalesce(sni, tostring(RemoteIP)), 6), R = max(R),
            FileOps = take_any(FileOps), Renames = take_any(Renames), Deletes = take_any(Deletes), RwExtHits = take_any(RwExtHits),
            SampleFiles = take_any(SampleFiles), BurstTime = min(BurstTime) by DeviceId, DeviceName, ja4_, ja4s_
| extend Verdict = case(RwExtHits >= 8, "CRITICAL - ransomware-extension burst + rare JA4 callout",
                        (Renames >= 250 and Deletes >= 100) or RwExtHits >= 3, "HIGH - mass file-op burst + rare JA4 callout",
                        "MEDIUM - moderate rename/delete burst + rare JA4 callout (possible staged / low-and-slow encryption)")
| project Verdict, DeviceName, JA4 = ja4_, ServerJA4S = ja4s_, Rarity = round(R, 2), FileOps, Renames, Deletes, RwExtHits,
          CalloutConns, Dests, SampleFiles, BurstTime
| sort by RwExtHits desc, FileOps desc
```

**Output columns**

| Column | What it means |
|---|---|
| `Verdict` | Critical/High/Medium text based on ransomware extension hits and file-operation volume. |
| `DeviceName` | Device with the file burst and rare JA4 callout. |
| `JA4` | Client JA4 fingerprint. |
| `ServerJA4S` | Server JA4S fingerprint. |
| `Rarity` | Tenant-relative rarity score for the JA4. |
| `FileOps` | Total file operations in the burst. |
| `Renames` | Number of file rename events. |
| `Deletes` | Number of file delete events. |
| `RwExtHits` | Count of files with known ransomware-like extensions. |
| `CalloutConns` | Number of rare JA4 callouts around the burst. |
| `Dests` | Up to six contacted destinations. |
| `SampleFiles` | Up to eight sample file names from the burst. |
| `BurstTime` | Start time of the earliest summarized burst. |

**Reading this output:** Read `Verdict`, `RwExtHits`, `Renames`, `Deletes`, `FileOps`, and `Dests` first. Normal bulk activity is filtered by high thresholds and still must have a rare JA4 within ±30 minutes. Suspicious rows show ransomware extensions or mass rename/delete shape plus rare C2-style check-in; this panel does not project `Why`, so `Verdict` and the file-operation counts carry the reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| Critical | `RwExtHits >= 8` | Ransomware-extension burst plus rare JA4 callout | Escalate immediately and consider containment. |
| High | `(Renames >= 250 and Deletes >= 100)` or `RwExtHits >= 3` | Mass file-operation burst plus rare JA4 callout | Triage host for active encryption/staging. |
| Medium | Remaining rows that passed burst gates and rare JA4 correlation | Moderate rename/delete burst with possible staged or low-and-slow encryption | Validate file samples and recent admin jobs. |

**Tunables:** `lookback` → history; `minRarity` → JA4 rarity cutoff; `rwExt` → exact ransomware extension list; `rwTerms` → term-index prefilter for scale; file burst thresholds (`FileOps`, `Renames`, `Deletes`, `RwExtHits`) → sensitivity; ±30-minute window → callout-to-burst correlation.

**False positives:** Backup, migration, or software deployment jobs → volume thresholds and rare JA4 correlation reduce ordinary bulk file changes → check maintenance windows and `SampleFiles`. Legitimate archive/encryption tools → ransomware extension hits drive Critical/High → validate extensions, process owner, and destination.

**Example row:** "`Verdict=CRITICAL - ransomware-extension burst + rare JA4 callout`, `RwExtHits=12`, `Renames=310`, `Deletes=145`, `Dests=['c2.example']` → Critical because ransomware-like file extensions and mass file operations align with rare TLS check-in."

**Next step:** Treat Critical rows as active incident candidates: confirm encryption scope, isolate if active, preserve `SampleFiles`, and escalate to IR.

### 09 Privileged or service identity on rare-JA4 host   (Corroboration · `wb_privja4.kql`)
**What it detects:** A device with a recent privileged or service-account logon that also makes a rare JA4 callout, with higher priority for non-browser JA4.

**Hunt hypothesis:** "An implant on an admin workstation or service-account host shows up as rare or non-browser TLS from a device where privileged identity recently logged on."

**MITRE ATT&CK:** T1078 (Valid accounts) · T1071.001 (Web protocols)

**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, public JA4) — device, destination, JA4/JA4S, non-browser flag; `DeviceLogonEvents` (`AccountName matches privAcctRegex`) — privileged/service account names and last logon; rarity-gated: yes; second source: `DeviceLogonEvents`.

**How it works:** The query calculates rarity for public JA4 values and marks JA4s as non-browser when the b-section is not in the browser allowlist. It infers privileged/service identity from account-name patterns because this KQL notes no `IdentityInfo` table is available, then joins rare JA4 connections to the device's last privileged/service logon within ±12 hours. If `DeviceLogonEvents` is missing or account names do not match the regex, the panel returns no rows.

**Sample query (excerpt):** the detection heart of `wb_privja4.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | extend Rhost = iff(totalDevs  <= 1, 1.0, max_of(0.0, log(todouble(totalDevs)  / todouble(Devs))  / log(todouble(totalDevs))))
    | extend Rconn = iff(totalConns <= 1, 1.0, max_of(0.0, log(todouble(totalConns) / todouble(Conns)) / log(todouble(totalConns))))
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity
    | project ja4_, R;
// …
ssl
| lookup kind=inner rare on ja4_
| join kind=inner privLogon on DeviceId
| where ConnTime between (LastLogon - 12h .. LastLogon + 12h)
| summarize Conns = count(), FirstSeen = min(ConnTime), LastSeen = max(ConnTime),
            Dests = make_set(coalesce(sni, tostring(RemoteIP)), 8), PrivAccts = take_any(PrivAccts),
            AnyNonBrowser = max(nonBrowser), R = max(R) by DeviceId, DeviceName, ja4_, ja4s_
| extend Verdict = iff(AnyNonBrowser == 1, "HIGH - privileged/service account on device with rare NON-BROWSER JA4",
                                            "MEDIUM - privileged/service account on device with rare JA4")
| project Verdict, DeviceName, PrivAccounts = PrivAccts, JA4 = ja4_, ServerJA4S = ja4s_, NonBrowser = AnyNonBrowser,
          Rarity = round(R, 2), Conns, Dests, FirstSeen, LastSeen
| sort by Verdict asc, Rarity desc
```

**Output columns**

| Column | What it means |
|---|---|
| `Verdict` | High when rare JA4 is non-browser; Medium when rare JA4 is browser-like. |
| `DeviceName` | Device with the privileged/service logon and rare JA4. |
| `PrivAccounts` | Up to five matching privileged/service account names. |
| `JA4` | Client JA4 fingerprint. |
| `ServerJA4S` | Server JA4S fingerprint. |
| `NonBrowser` | `1` when the JA4 b-section is not in the browser allowlist. |
| `Rarity` | Tenant-relative rarity score for the JA4. |
| `Conns` | Count of matching rare JA4 connections. |
| `Dests` | Up to eight destinations contacted with the rare JA4. |
| `FirstSeen` | First matching rare JA4 connection in the summary. |
| `LastSeen` | Last matching rare JA4 connection in the summary. |

**Reading this output:** Read `Verdict`, `PrivAccounts`, `NonBrowser`, `Rarity`, and `Dests` first. Normal admin browsing with common browser JA4 should not survive the rarity and non-browser emphasis. Suspicious rows show service/admin identity near rare TLS, especially when `NonBrowser=1`; this panel does not project `Why`, so `Verdict`, `PrivAccounts`, and destination columns carry the reasoning.

**Verdict / severity bands**

| Value | Threshold | Means | Action |
|---|---|---|---|
| High | `AnyNonBrowser == 1` | Privileged/service account on a device with rare non-browser JA4 | Escalate if destination or process is not approved. |
| Medium | `AnyNonBrowser == 0` | Privileged/service account on a device with rare JA4 | Validate account role, browser/app use, and destination. |

**Tunables:** `lookback` → history; `minRarity` → rare JA4 cutoff; `privAcctRegex` → privileged/service account naming standard; `browserBsec` → browser b-section allowlist; ±12-hour window around `LastLogon` → identity-to-callout correlation.

**False positives:** Broad service-account naming patterns → `privAcctRegex` is tunable and the query notes `IdentityInfo` is not used → verify the account is actually privileged or service-owned. Approved admin tools → rare JA4 and non-browser flag raise priority → confirm expected tool, destination, and change window.

**Example row:** "`Verdict=HIGH - privileged/service account on device with rare NON-BROWSER JA4`, `PrivAccounts=['svc-backup']`, `NonBrowser=1`, `Rarity=0.93`, `Dests=['198.51.100.10']` → High because a service identity was recently present on a host making rare non-browser TLS."

**Next step:** Verify the account's role and active session, check process/destination context on the host, and escalate if a privileged identity could be exposed to unknown C2.

### 01 LOTS / domain-fronting paradox   (Destination & inventory · `wb_lots.kql`)
**What it detects:** Rare client-and-server TLS fingerprint pairs (`ja4_` + `ja4s_`) reaching trusted cloud, CDN, or SaaS hostnames from non-browser processes.
**Hunt hypothesis:** "Malware living off trusted sites shows up as a rare JA4+JA4S pair connecting to a trusted SNI from a process that should not browse the web."
**MITRE ATT&CK:** T1071.001 (Web protocols) · T1102 (Web service)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `DeviceId`, `DeviceName`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessVersionInfoCompanyName`; rarity-gated: yes (`minRarity = 0.7`); known-bad: n/a
**How it works:** The query first finds rare `ja4_`+`ja4s_` pairs across the estate, then keeps only pairs that contacted public trusted SNIs such as GitHub, Discord, Telegram, Azure Blob, ngrok, or trycloudflare. It joins those rare TLS flows to `ConnectionSuccess` process attribution and suppresses expected browser and web-app processes. It labels the remaining rows by process risk: LOLBIN, user/temp path, or other non-browser process.

**Sample query (excerpt):** the detection heart of `wb_lots.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
    | extend R = min_of(Rhost, Rconn)
    | where R >= minRarity and AnyTrusted);
// …
| extend Verdict = case(
    AnyLolbin,   "CRITICAL - LOLBIN to trusted cloud SNI",
    AnyUserPath, "HIGH - user/temp-path process to trusted cloud SNI",
                 "MEDIUM - non-browser process to trusted cloud SNI")
| extend Why = strcat(
    "Rare JA4 to trusted CDN/cloud from non-browser (LOTS paradox); ",
    iff(AnyLolbin,   strcat("LOLBIN [", tostring(Procs), "]; "), ""),
    iff(AnyUserPath, "user/temp-path proc; ", ""),
    strcat("TLS-lib=", LibHint, "; R=", round(R, 2)))
// Numeric sort key so CRITICAL < HIGH < MEDIUM regardless of alphabetical order.
| extend SevOrd = case(AnyLolbin, 1, AnyUserPath, 2, 3)
| project Verdict, ja4_, ja4s_, Why, Procs, SampleSNIs, TrustedSnis,
          LibHint, Devices, Conns, SampleDevices, AnyLolbin, AnyUserPath,
          ProcFolders, Rarity = round(R, 2), FirstSeen, LastSeen, SevOrd
| sort by SevOrd asc, Devices asc, Conns asc
```
**Output columns** —
| Column | What it means |
|---|---|
| `Verdict` | Priority label derived from the process context. |
| `ja4_` | JA4 client TLS fingerprint; this describes the client TLS handshake shape. |
| `ja4s_` | JA4S server TLS fingerprint; this describes the server response shape. |
| `Why` | Plain-English reasoning: rare JA4 to trusted cloud, process clues, TLS library hint, and rarity score. |
| `Procs` | Process names observed on matching flows. |
| `SampleSNIs` | Sample requested hostnames from matching public trusted destinations. |
| `TrustedSnis` | Trusted SNI values seen for the rare pair during rarity aggregation. |
| `LibHint` | JA4 b-section library guess, such as Chromium, Firefox, Python, Go, WinINET, WinHTTP, or SoftEther. |
| `Devices` / `Conns` | Number of distinct devices and total matching connections. |
| `SampleDevices` | Example device names that produced the traffic. |
| `AnyLolbin` | `true` when a living-off-the-land Windows utility such as PowerShell, rundll32, mshta, or certutil appeared. |
| `AnyUserPath` | `true` when the process path includes a user profile, temp, downloads, or AppData location. |
| `ProcFolders` | Example process folder paths. |
| `Rarity` | Rounded rarity score `R`; closer to 1 means fewer devices/connections in the estate use that pair. |
| `FirstSeen` / `LastSeen` | First and last observed matching connection times in the lookback. |
**Reading this output:** Read `Verdict` first, then `Why`, then `Procs` and `SampleSNIs`. Normal trusted-SNI traffic should come from browsers or managed web apps, which this panel suppresses; suspicious rows are the paradox: a trusted destination plus an unexpected TLS client library or process. The `Why` column carries the evidence, including whether the row involved a LOLBIN, a user/temp path, and the JA4 rarity score.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| `CRITICAL - LOLBIN to trusted cloud SNI` | `AnyLolbin = true` | A commonly abused Windows utility reached a trusted cloud/SaaS endpoint using a rare JA4+JA4S pair. | Escalate immediately; collect process command line, parent process, destination, and device timeline. |
| `HIGH - user/temp-path process to trusted cloud SNI` | No LOLBIN, but `AnyUserPath = true` | A user-writable process location is contacting trusted infrastructure with a rare TLS shape. | Triage the binary owner, signer, hash, and recent download or execution events. |
| `MEDIUM - non-browser process to trusted cloud SNI` | Non-browser process, no LOLBIN or user/temp path | Unusual but not automatically malicious trusted-site usage. | Verify business purpose and suppress only after ownership is confirmed. |
**Tunables:** `lookback = 30d` → wider history improves rarity context but costs more; `minRarity = 0.7` → higher values show fewer, rarer pairs; `trustedSni` → expands or narrows the trusted-site list; `browserProcs` → controls expected browser/WebView suppression; `lolbinProcs` → controls CRITICAL process classification.
**False positives:** Approved updater or automation using GitHub/Slack/Azure → browser processes are suppressed and rows must be rare and public trusted-SNI → confirm signer, owner, install path, and change ticket before closing. Developer CLI or scripted SaaS access → not suppressed if it is not in browser lists → confirm the process is expected for that host and destination.
**Example row:** `Verdict="CRITICAL - LOLBIN to trusted cloud SNI"; Procs=["powershell.exe"]; SampleSNIs=["raw.githubusercontent.com"]; LibHint="Go"; Rarity=0.92` → CRITICAL because a rare Go-like TLS pair reached a trusted cloud hostname from PowerShell.
**Next step:** For CRITICAL or HIGH rows, open the device timeline and escalate to Tier-2/IR if the process is unsigned, user-writable, recently downloaded, or lacks an approved owner. For MEDIUM rows, verify ownership before suppression.

### 02 ECH / hidden-SNI   (Destination & inventory · `wb_ech.kql`)
**What it detects:** Public TLS connections where JA4 suggests Encrypted Client Hello (ECH) or hidden SNI, especially from non-browser or LOLBIN processes.
**Hunt hypothesis:** "SNI-hiding or ECH-capable tooling shows up as no-cleartext-SNI JA4 patterns or ECH bootstrap hostnames in Defender TLS telemetry."
**MITRE ATT&CK:** T1573 (Encrypted Channel) · T1090 (Proxy)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `DeviceId`, `DeviceName`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessVersionInfoCompanyName`; rarity-gated: no; known-bad: n/a
**How it works:** The query looks for two ECH proxies: an outer SNI such as `cloudflare-ech.com`, `*-ech.com`, or names containing `ech.`, and JA4 strings whose SNI-position flag is `i` with browser-like ALPN `h1` or `h2` to a public IP. It joins candidate TLS flows to process names and classifies browser ECH as informational while prioritizing LOLBIN and user-path non-browser activity. `LibHint` comes from the JA4 b-section, the middle library hash in the JA4 string.

**Sample query (excerpt):** the detection heart of `wb_ech.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| extend Verdict = case(
    AnyLolbin,
        "HIGH - ECH/no-SNI from LOLBIN (triage immediately)",
    not(AnyBrowserProc) and AnyUserPath,
        "MEDIUM - ECH from user-path non-browser process",
    not(AnyBrowserProc),
        "REVIEW - ECH from non-browser process",
        "INFO - ECH from browser (expected; low priority)")
// …
| extend SevOrd = case(
    AnyLolbin,                           1,
    not(AnyBrowserProc) and AnyUserPath, 2,
    not(AnyBrowserProc),                 3,
    4)
| project Verdict, EchCategory, ja4_, ja4s_, Why, Procs, LibHint,
          SampleDests, SampleDevices, Devices, Conns,
          AnyBrowserProc, AnyLolbin, AnyUserPath, FirstSeen, LastSeen, SevOrd
| sort by SevOrd asc, Devices desc
```
**Output columns** —
| Column | What it means |
|---|---|
| `Verdict` | Priority label based on process type and path. |
| `EchCategory` | Detection path: `ECH-bootstrap-SNI` or `no-SNI+browser-ALPN (ECH candidate)`. |
| `ja4_` / `ja4s_` | Client and server TLS fingerprints for the matching traffic. |
| `Why` | Plain-English reasoning: ECH category, browser/non-browser context, LOLBIN or user path, TLS library, and ALPN. |
| `Procs` | Processes attributed to the hidden-SNI flows; `(unattributed)` means no `ConnectionSuccess` process match was found. |
| `LibHint` | TLS library hint from the JA4 b-section. |
| `SampleDests` | Example SNI values or remote IPs. |
| `SampleDevices` | Example devices. |
| `Devices` / `Conns` | Distinct device count and matching connection count. |
| `AnyBrowserProc` | `true` when a known browser or browser-like app initiated the flow. |
| `AnyLolbin` | `true` when a LOLBIN process initiated the flow. |
| `AnyUserPath` | `true` when the process folder is user-writable or temporary. |
| `FirstSeen` / `LastSeen` | First and last matching observations. |
**Reading this output:** Read `Verdict`, then `EchCategory`, then `Why`. Browser ECH is increasingly normal and appears as INFO; non-browser ECH is suspicious because it can hide the real destination from SNI-based inspection. The `Why` column carries the reasoning, including the ALPN value and whether the traffic was browser-initiated, non-browser-initiated, user-path, or LOLBIN.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH - ECH/no-SNI from LOLBIN (triage immediately)` | `AnyLolbin = true` | A living-off-the-land utility used hidden-SNI/ECH-like TLS. | Escalate immediately and review command line, parent process, and destination. |
| `MEDIUM - ECH from user-path non-browser process` | Not browser and `AnyUserPath = true` | A user-writable non-browser process hid the cleartext SNI. | Triage the binary, signer, and recent file/download events. |
| `REVIEW - ECH from non-browser process` | Not browser, not user path, not LOLBIN | Non-browser ECH may be a proxy, agent, or tool. | Verify approved owner and purpose. |
| `INFO - ECH from browser (expected; low priority)` | Browser process present | Expected modern browser ECH behavior. | Usually no action unless the destination or host is otherwise suspicious. |
**Tunables:** `lookback = 30d` → controls history; `browserProcs` → controls INFO classification; `lolbinProcs` → controls HIGH classification; ECH hostname logic (`cloudflare-ech.com`, `*-ech.com`, `ech.`) → controls bootstrap detection; ALPN set `h1`/`h2` → controls no-SNI browser-like candidate matching.
**False positives:** Normal Chrome/Edge/Firefox ECH → browser processes are labelled INFO, not escalated → verify only if the destination/device has other alerts. Approved privacy proxy or vendor agent → non-browser rows remain visible → confirm signer, owner, and expected destination before suppressing.
**Example row:** `Verdict="HIGH - ECH/no-SNI from LOLBIN (triage immediately)"; EchCategory="no-SNI+browser-ALPN (ECH candidate)"; Procs=["rundll32.exe"]; LibHint="other"; SampleDests=["203.0.113.10"]` → HIGH because a LOLBIN used a hidden-SNI pattern to a public destination.
**Next step:** Escalate HIGH immediately. For MEDIUM or REVIEW, validate whether the process is an approved browser component, proxy, VPN, or vendor agent; escalate if it is unsigned, user-writable, or unexplained.

### 03 Shadow-IT SaaS access   (Destination & inventory · `wb_shadowit.kql`)
**What it detects:** Python, Go, SoftEther, or unknown automation-library TLS fingerprints reaching public non-Microsoft SaaS/API destinations.
**Hunt hypothesis:** "Unapproved scripts, agents, or SaaS integrations show up as automation-library JA4 b-sections connecting to external services outside Microsoft-managed destinations."
**MITRE ATT&CK:** T1567 (Exfiltration Over Web Service)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `DeviceId`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessVersionInfoCompanyName`; rarity-gated: no; known-bad: n/a
**How it works:** The query extracts the JA4 b-section, which is a stable TLS-library hash, and suppresses browser stacks, OS TLS stacks, high-prevalence unknown b-sections, private IPs, and Microsoft destinations. It labels remaining public SaaS/API traffic as Python, Go, SoftEther, or unknown, then joins to process attribution. Interest level is based on whether the process is a known dev/automation tool and whether it ran from a user/temp path.

**Sample query (excerpt):** the detection heart of `wb_shadowit.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
| extend Interest = case(
    not(AnyDevProc) and AnyUserPath,
        "HIGH-INTEREST - non-dev-tool in user/temp path",
    not(AnyDevProc),
        "MEDIUM-INTEREST - process not in dev-tool list",
        "LOW-INTEREST - known dev/automation tool (expected)")
| extend Why = strcat(
    LibraryName, " TLS library to external SaaS/API; proc=", Proc, "; ",
    iff(not(AnyDevProc), "NOT a known dev tool; ", "known dev tool; "),
    iff(AnyUserPath,     "user/temp path; ", ""),
    strcat("TLS-library b-section ", bsec))
// SevOrd for sort: HIGH-INTEREST=1, MEDIUM=2, LOW=3
| extend SevOrd = case(not(AnyDevProc) and AnyUserPath, 1, not(AnyDevProc), 2, 3)
| project Interest, LibraryName, bsec, Proc, SampleSNIs, SampleFolders,
          SampleSigners, Devices, Conns, AnyDevProc, AnyUserPath,
          Why, FirstSeen, LastSeen, SevOrd
| sort by SevOrd asc, Devices desc, Conns desc
| project-away SevOrd
```
**Output columns** —
| Column | What it means |
|---|---|
| `Interest` | Inventory priority label; it is not an alert severity. |
| `LibraryName` | TLS library inferred from the JA4 b-section: Python, Go, SoftEther, or unknown. |
| `bsec` | JA4 b-section value, the middle hash used as the TLS-library identifier. |
| `Proc` | Attributed process name, or `(unattributed)` when no process match exists. |
| `SampleSNIs` | Example external SaaS/API hostnames or IPs. |
| `SampleFolders` | Example process folder paths. |
| `SampleSigners` | Example process signer/company values. |
| `Devices` / `Conns` | Distinct device count and matching connection count. |
| `AnyDevProc` | `true` when the process is in the known developer/automation executable list. |
| `AnyUserPath` | `true` when the process path is user-writable or temporary. |
| `Why` | Plain-English reasoning. It ends with `TLS-library b-section <hash>` so you can see the exact library fingerprint driving the row. |
| `FirstSeen` / `LastSeen` | First and last observations in the lookback. |
**Reading this output:** Read `Interest`, then `Why`, then `Proc`, `LibraryName`, and `SampleSNIs`. LOW-INTEREST usually means expected developer or automation tooling; HIGH-INTEREST means a non-dev process in a user/temp path is using an automation TLS library to reach external SaaS/API. The `Why` column carries the reasoning and includes the exact TLS-library b-section hash.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| `HIGH-INTEREST - non-dev-tool in user/temp path` | `AnyDevProc = false` and `AnyUserPath = true` | A user-writable non-dev process is using an automation-library TLS stack externally. | Triage as potential unapproved tool, script, loader, or exfiltration helper. |
| `MEDIUM-INTEREST - process not in dev-tool list` | `AnyDevProc = false` and no user/temp path | The process is not recognized as expected dev/automation tooling. | Identify owner, signer, destination purpose, and whether SaaS access is approved. |
| `LOW-INTEREST - known dev/automation tool (expected)` | `AnyDevProc = true` | Expected tools such as Python, Go, curl, git, cloud CLIs, or CI tooling. | Inventory or tune only if the destination is unapproved. |
**Tunables:** `lookback = 30d` → controls history; `suppressBsec` → suppresses browser and OS-layer stacks; `msSni` → defines Microsoft-managed destination suppression; `devProcs` → controls LOW-INTEREST classification; `commonBsec` threshold `Devs > 1000` → suppresses fleet-wide unknown system libraries while keeping Python, Go, and SoftEther.
**False positives:** Approved developer workstation or CI runner → known dev tools are labelled LOW-INTEREST → confirm the destination and owner before suppressing. Vendor agent using Go/Python TLS → Microsoft destinations and common browser/OS stacks are suppressed, but vendor SaaS remains visible → verify signer, installation path, and business owner.
**Example row:** `Interest="HIGH-INTEREST - non-dev-tool in user/temp path"; LibraryName="Python"; Proc="updater.exe"; SampleFolders=["C:\\Users\\analyst\\AppData\\Local\\Temp"]; Why="Python TLS library to external SaaS/API; proc=updater.exe; NOT a known dev tool; user/temp path; TLS-library b-section 85036bcba153"` → HIGH-INTEREST because a non-dev executable in a user-writable path used the Python TLS-library fingerprint externally.
**Next step:** For HIGH-INTEREST, identify the process owner and destination immediately; escalate if the process is unsigned, recently downloaded, unknown to IT, or contacting storage/chat/API services without approval. For MEDIUM/LOW, document or tune approved business use.

### 04 Deprecated TLS compliance   (Destination & inventory · `wb_deprecated.kql`)
**What it detects:** Clients in the estate that initiate TLS 1.0, TLS 1.1, SSL 3.0, or SSL 2.0.
**Hunt hypothesis:** "Legacy clients that violate TLS 1.2+ compliance requirements show up as JA4 version codes `10`, `11`, `s3`, or `s2` in TLS inspection telemetry."
**MITRE ATT&CK:** n/a - compliance inventory
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.server_name`, `DeviceId`, `DeviceName`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`; rarity-gated: no; known-bad: n/a
**How it works:** The query reads the JA4 version field and keeps only legacy TLS/SSL codes. It marks whether the remote IP is public, then joins the legacy flows to process names. Results are summarized by TLS version, JA4 value, and remote port so you can see affected clients and destinations.

**Sample query (excerpt):** the detection heart of `wb_deprecated.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
ssl
| join hint.shufflekey=DeviceId kind=leftouter procs on DeviceId, RemoteIP, RemotePort
| extend TLSVersion = case(tlsVer == "10", "TLS 1.0", tlsVer == "11", "TLS 1.1", tlsVer == "s3", "SSL 3.0", "SSL 2.0")
| summarize Connections = count(), Devices = dcount(DeviceId, 4), SampleDevices = make_set(DeviceName, 5),
            SampleProcs = make_set(Proc, 5), SampleDests = make_set(coalesce(sni, tostring(RemoteIP)), 6),
            AnyPublic = max(isPublic), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by TLSVersion, ja4_, RemotePort
| extend Concern = iff(AnyPublic, "PUBLIC legacy-TLS (PCI/FedRAMP concern)", "internal legacy-TLS")
| project TLSVersion, Concern, ja4_, RemotePort, Devices, Connections, SampleProcs, SampleDevices, SampleDests, FirstSeen, LastSeen
| sort by Devices desc, Connections desc
```
**Output columns** —
| Column | What it means |
|---|---|
| `TLSVersion` | Decoded legacy protocol: TLS 1.0, TLS 1.1, SSL 3.0, or SSL 2.0. |
| `Concern` | Public-vs-internal compliance concern. |
| `ja4_` | Client JA4 fingerprint that negotiated the legacy version. |
| `RemotePort` | Destination port used by the legacy flow. |
| `Devices` / `Connections` | Distinct device count and total legacy connections. |
| `SampleProcs` | Example processes that initiated legacy TLS. |
| `SampleDevices` | Example affected devices. |
| `SampleDests` | Example SNI values or remote IPs. |
| `FirstSeen` / `LastSeen` | First and last legacy observations in the lookback. |
**Reading this output:** Read `Concern` first, then `TLSVersion`, `SampleProcs`, and `SampleDests`. Internal legacy TLS may be a known compatibility exception; public legacy TLS is the higher compliance concern because the client is negotiating weak crypto outside the estate. There is no `Why` column in this panel; the evidence is the decoded `TLSVersion`, destination exposure in `Concern`, and the sample process/destination columns.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| `PUBLIC legacy-TLS (PCI/FedRAMP concern)` | `AnyPublic = true` in the query summary | A client used legacy TLS/SSL to a public destination. | Create a remediation ticket and escalate if the process or destination is unknown. |
| `internal legacy-TLS` | No public destination observed | Legacy TLS stayed inside private IP space. | Validate whether an approved exception exists and schedule upgrade/removal. |
**Tunables:** `lookback = 30d` → controls history; legacy version list `("10","11","s3","s2")` → defines what counts as deprecated; flow-key process join → limits process attribution to exact legacy flows.
**False positives:** Approved legacy internal application → rows are separated as `internal legacy-TLS` when not public → confirm exception owner, compensating controls, and upgrade plan. Lab scanner or compatibility test → summarized by process and destination → verify expected test window and scope.
**Example row:** `TLSVersion="TLS 1.0"; Concern="PUBLIC legacy-TLS (PCI/FedRAMP concern)"; RemotePort=443; SampleProcs=["legacyclient.exe"]; SampleDests=["legacy.example.com"]` → public compliance concern because a client negotiated TLS 1.0 to an external service.
**Next step:** For public rows, notify the asset/application owner and escalate to Tier-2 if the process is unknown, user-installed, or tied to sensitive systems. For internal rows, confirm documented exception and remediation date.

### 05 Structurally-impossible JA4   (Destination & inventory · `wb_impossible.kql`)
**What it detects:** JA4 fingerprints that are internally inconsistent or strongly tool-like, such as legacy TLS with ALPN, zero extensions to public hosts, QUIC on non-standard ports, or a documented mass-scanner prefix.
**Hunt hypothesis:** "Synthetic clients, scanners, or hand-rolled TLS tools show up as JA4 structures that normal TLS stacks should not be able to produce."
**MITRE ATT&CK:** T1595 (Active Scanning)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.server_name`, `DeviceId`, `DeviceName`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`; rarity-gated: no; known-bad: n/a
**How it works:** The query decodes JA4 protocol, TLS version, ALPN, cipher count, and extension count. It flags five rule families: TLS 1.0/1.1 with ALPN, legacy TLS with more than 60 ciphers, zero TLS extensions to a public destination, QUIC on a port other than 80 or 443, and JA4 values starting with `t11d6911h9`. It joins only flagged flows to process names and summarizes by `ja4_`.

**Sample query (excerpt):** the detection heart of `wb_impossible.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
ssl
| join hint.shufflekey=DeviceId kind=leftouter procs on DeviceId, RemoteIP, RemotePort
| extend Reason = strcat(
    iff(r_tls11alpn, "legacy-TLS with ALPN (impossible); ", ""),
    iff(r_legacyManyCiph, "legacy-TLS catch-all cipher list (scanner); ", ""),
    iff(r_noExtPub, "zero TLS extensions to public; ", ""),
    iff(r_quicNonStd, "QUIC on non-standard port; ", ""),
    iff(r_scanner, "known mass-scanner prefix; ", ""))
| summarize Connections = count(), Devices = dcount(DeviceId, 4), SampleDevices = make_set(DeviceName, 5),
            SampleProcs = make_set(Proc, 5), SampleDests = make_set(coalesce(sni, tostring(RemoteIP)), 6),
            AnyPublic = max(isPublic), Reason = take_any(Reason), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by ja4_
| project ja4_, Reason, Devices, Connections, AnyPublic, SampleProcs, SampleDevices, SampleDests, FirstSeen, LastSeen
| sort by Connections desc
```
**Output columns** —
| Column | What it means |
|---|---|
| `ja4_` | Client JA4 fingerprint that matched at least one structural rule. |
| `Reason` | Rule evidence, such as `legacy-TLS with ALPN (impossible)`, `zero TLS extensions to public`, `QUIC on non-standard port`, or `known mass-scanner prefix`. |
| `Devices` / `Connections` | Distinct device count and total matching connections. |
| `AnyPublic` | `true` when any matching flow went to a public IP. |
| `SampleProcs` | Example processes attributed to matching flows. |
| `SampleDevices` | Example affected devices. |
| `SampleDests` | Example SNI values or remote IPs. |
| `FirstSeen` / `LastSeen` | First and last matching observations. |
**Reading this output:** Read `Reason` first, then `AnyPublic`, `SampleProcs`, and `Connections`. A normal TLS stack should not produce legacy TLS with ALPN, and public zero-extension clients are suspicious because they look primitive or hand-rolled. This panel uses `Reason` instead of `Why`; `Reason` carries the detection evidence.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| Structural impossibility | `Reason` includes `legacy-TLS with ALPN (impossible)` | The JA4 combination should not occur in a normal TLS implementation. | Treat as high-priority unless tied to approved scanner or lab tooling. |
| Scanner/tool tell | `Reason` includes `legacy-TLS catch-all cipher list (scanner)` or `known mass-scanner prefix` | The JA4 resembles mass-scanner behavior. | Verify whether the source is an approved scanner; otherwise escalate. |
| Primitive public client | `Reason` includes `zero TLS extensions to public` | A basic or hand-rolled TLS client contacted a public host. | Review process, signer, command line, and destination. |
| QUIC port anomaly | `Reason` includes `QUIC on non-standard port` | QUIC appeared outside normal HTTP ports. | Confirm approved application behavior or proxy testing. |
**Tunables:** `lookback = 30d` → controls history; `cipherCnt > 60` → scanner threshold; `extCnt == 0 and isPublic` → primitive public-client threshold; `RemotePort != 443 and RemotePort != 80` → QUIC port anomaly definition; scanner prefix `t11d6911h9` → documented mass-scanner match.
**False positives:** Approved vulnerability scanner or TLS test harness → no broad suppression is applied, but process and destination samples are shown → confirm scanner ownership, scope, and schedule. Lab or QA protocol testing → exact rule reason is visible → validate the test host and close with owner evidence.
**Example row:** `ja4_="t11d6911h9..."; Reason="legacy-TLS with ALPN (impossible); known mass-scanner prefix;"; AnyPublic=true; SampleProcs=["scanner.exe"]; Connections=42` → scanner/tool tell because the JA4 has a documented mass-scanner prefix and an impossible TLS 1.1+ALPN structure.
**Next step:** If the source is not an approved scanner or test host, escalate to Tier-2 with the device, process, sample destinations, and `Reason`. If it is approved, document the owner and expected schedule.

### 06 Fleet hygiene / cross-OS anomaly   (Destination & inventory · `wb_hygiene.kql`)
**What it detects:** Device-level TLS hygiene anomalies: OS-to-TLS-library contradictions and devices with more than three times the fleet-median number of distinct JA4 fingerprints.
**Hunt hypothesis:** "Cross-compiled implants, Wine/WSL execution, uTLS spoofing, or fingerprint-randomizing tools show up as TLS-library fingerprints that contradict the device OS or as abnormal JA4 proliferation on one device."
**MITRE ATT&CK:** n/a - hygiene inventory
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `DeviceId`, `DeviceName`; `DeviceInfo` — `OSPlatform`; rarity-gated: no; known-bad: n/a
**How it works:** The query builds one per-device/per-JA4 aggregate, then joins the device's latest `OSPlatform` from `DeviceInfo`. One branch flags impossible OS/library combinations: Safari/WebKit b-section outside Apple platforms, or WinINET/WinHTTP b-sections outside Windows. The other branch flags the top devices whose distinct JA4 count is greater than three times the fleet median.

**Sample query (excerpt):** the detection heart of `wb_hygiene.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
let contradictions =
    perDJ
    | where ja4_ contains "a09f3c656075" or ja4_ contains "d83cc789557e" or ja4_ contains "76e208dd3e22"
    | join kind=inner devInfo on DeviceId
    | where isnotempty(OSPlatform)
    | extend libIsSafari = (ja4_ contains "a09f3c656075"), libIsWinINET = (ja4_ contains "d83cc789557e"), libIsWinHTTP = (ja4_ contains "76e208dd3e22")
    | extend libLabel = case(libIsSafari, "Safari/WebKit (Apple-only, b=a09f3c656075)", libIsWinINET, "WinINET (Windows-only, b=d83cc789557e)", libIsWinHTTP, "WinHTTP (Windows-only, b=76e208dd3e22)", "other")
    | extend isContradiction = ((libIsSafari and not(OSPlatform in~ ("macOS","iOS"))) or (libIsWinINET and not(OSPlatform startswith "Windows")) or (libIsWinHTTP and not(OSPlatform startswith "Windows")))
    | where isContradiction
    | summarize DeviceName = take_any(DeviceName), OSPlatform = take_any(OSPlatform), ContradictingJA4s = make_set(ja4_, 10), DistinctJA4s = dcount(ja4_, 4), ContraLibs = make_set(libLabel, 5), Conns = sum(Conns), FirstSeen = min(FirstSeen), LastSeen = max(LastSeen) by DeviceId
    | extend Reason = strcat("OSPlatform=", OSPlatform, " emitting library mismatch: ", strcat_array(ContraLibs, "; "), " (", tostring(DistinctJA4s), " contradicting JA4(s)) - WSL/Wine/cross-compiled implant or uTLS fingerprint spoof")
    | project FindingType = "OS-Fingerprint Contradiction", DeviceId, DeviceName, OSPlatform, DistinctJA4s, SampleJA4s = ContradictingJA4s, Conns, Reason, FirstSeen, LastSeen;
// …
union contradictions, proliferators
| extend FTypeOrder = iff(FindingType == "OS-Fingerprint Contradiction", 1, 2)
| project FindingType, DeviceName, DeviceId, OSPlatform, DistinctJA4s, SampleJA4s, Conns, Reason, FirstSeen, LastSeen, FTypeOrder
| sort by FTypeOrder asc, DistinctJA4s desc, Conns desc
| project-away FTypeOrder
```
**Output columns** —
| Column | What it means |
|---|---|
| `FindingType` | `OS-Fingerprint Contradiction` or `JA4 Proliferation`. |
| `DeviceName` / `DeviceId` | Affected asset. |
| `OSPlatform` | Latest device OS platform from `DeviceInfo`; `(unknown)` is used for proliferation rows without OS data. |
| `DistinctJA4s` | Count of distinct JA4 fingerprints involved in the finding. |
| `SampleJA4s` | Example JA4 values from the device. |
| `Conns` | Total matching TLS connections in the aggregate. |
| `Reason` | Plain-English explanation of the OS/library mismatch or proliferation ratio. |
| `FirstSeen` / `LastSeen` | First and last observations for the finding. |
**Reading this output:** Read `FindingType`, then `Reason`, then `OSPlatform` and `SampleJA4s`. Normal devices should mostly emit TLS-library fingerprints that match their OS and application stack; suspicious rows show Apple-only b-sections on non-Apple OSes, Windows-only b-sections on non-Windows OSes, or a device producing far more JA4s than the fleet median. This panel uses `Reason` instead of `Why`; `Reason` carries the evidence and candidate explanations.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| `OS-Fingerprint Contradiction` | Safari/WebKit b-section on non-macOS/iOS, or WinINET/WinHTTP b-section on non-Windows | TLS library fingerprint contradicts recorded OS. | Validate asset inventory, WSL/Wine/cross-platform tooling, and process context; escalate if unexplained. |
| `JA4 Proliferation` | `DistinctJA4s > 3 * fleet median`; top 20 by distinct count | Device emits unusually many TLS fingerprints. | Check for scanners, bulk tools, randomizing implants, or broad automation deployment. |
**Tunables:** `lookback = 30d` → controls history; contradiction b-sections `a09f3c656075`, `d83cc789557e`, `76e208dd3e22` → define OS/library mismatch rules; proliferation threshold `DistinctJA4s > 3 * medianJA4` → controls sensitivity; `top 20` → limits proliferation output.
**False positives:** Stale or incorrect asset OS inventory → latest `DeviceInfo.OSPlatform` is used but may still lag → verify the device record. Approved WSL/Wine/cross-platform app or scanner → no suppression is applied → confirm owner, install path, and expected JA4 diversity before closing.
**Example row:** `FindingType="OS-Fingerprint Contradiction"; DeviceName="WIN-01"; OSPlatform="Windows10"; SampleJA4s=["...a09f3c656075..."]; Reason="OSPlatform=Windows10 emitting library mismatch: Safari/WebKit (Apple-only, b=a09f3c656075) ..."` → anomaly because an Apple-only WebKit TLS-library hash appeared on a Windows device.
**Next step:** Validate the asset OS and known cross-platform tooling. Escalate if the contradiction is real and the process owner is unknown, or if JA4 proliferation appears on a non-scanner workstation/server.

### 07 Process-to-JA4 baseline   (Destination & inventory · `wb_baseline.kql`)
**What it detects:** Common process-to-TLS-library relationships in the estate for known-good tuning and reference.
**Hunt hypothesis:** "Expected enterprise software shows up as repeated process-to-JA4 b-section pairs across many devices, and that catalog helps tune mismatch detections."
**MITRE ATT&CK:** n/a - reference
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`, `ConnectionSuccess`) — `AdditionalFields.ja4`, `AdditionalFields.server_name`, `DeviceId`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`, `InitiatingProcessVersionInfoCompanyName`; rarity-gated: no; known-bad: n/a
**How it works:** The query maps JA4 b-sections to known TLS libraries such as Chromium, Firefox, Safari/WebKit, Python, Go, WinINET, WinHTTP, and SoftEther. It joins TLS flows to process names and signers, then summarizes by process, library, and b-section. At very large scale the process join samples up to 5,000 SSL devices, so common pairs are preserved but per-device counts can be representative rather than exhaustive.

**Sample query (excerpt):** the detection heart of `wb_baseline.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
ssl
| join hint.shufflekey=DeviceId kind=inner procs on DeviceId, RemoteIP, RemotePort
| lookup kind=leftouter libMap on bsec
| extend Library = coalesce(lib, strcat("other (", bsec, ")"))
| summarize DistinctDevices = dcount(DeviceId, 4), TotalConns = sum(Conns), DistinctJA4s = dcount(ja4_, 4),
            Signers = make_set(Signer, 3), SampleSNIs = make_set(sni, 6), FirstSeen = min(FirstSeen), LastSeen = max(LastSeen)
        by Proc, Library, bsec
| project Proc, Library, bsec, DistinctDevices, TotalConns, DistinctJA4s, Signers, SampleSNIs, FirstSeen, LastSeen
| sort by DistinctDevices desc, TotalConns desc
```
**Output columns** —
| Column | What it means |
|---|---|
| `Proc` | Process name observed using the TLS library. |
| `Library` | Friendly TLS-library name from the embedded b-section map, or `other (<bsec>)`. |
| `bsec` | JA4 b-section hash that identifies the TLS library family. |
| `DistinctDevices` | Number of distinct devices observed for the process/library pair. |
| `TotalConns` | Total connections for the pair in the summarized data. |
| `DistinctJA4s` | Number of distinct full JA4 fingerprints seen for that process/library pair. |
| `Signers` | Example process signer/company values. |
| `SampleSNIs` | Example server names contacted by the pair. |
| `FirstSeen` / `LastSeen` | First and last observations. |
**Reading this output:** Read `Proc`, `Library`, `DistinctDevices`, and `SampleSNIs`. This is a reference catalog, not a verdict panel: high counts usually mean common known-good software such as Teams, OneDrive, Outlook, browsers, WinHTTP services, or enterprise agents. Use this panel to understand normal process-to-JA4 relationships before tuning allowlists or interpreting a mismatch panel.
**Tunables:** `lookback = 30d` → controls history; embedded `libMap` → controls b-section-to-library labels; `sample 5000` → bounds the process join at very large scale while preserving common pairs.
**False positives:** n/a for alerting because this panel has no verdict or severity. Baseline drift or sampling bias → common pairs are shown most-trusted first, but large fleets may use representative counts → confirm with owner/signers before using a pair as a suppression rule.
**Example row:** `Proc="teams.exe"; Library="Chromium (TCP)"; bsec="8daaf6152771"; DistinctDevices=800; SampleSNIs=["teams.microsoft.com"]` → reference-only known-good candidate because a common signed collaboration app uses a Chromium TLS-library b-section across many devices.
**Next step:** Use high-prevalence, well-owned pairs to tune allowlists for mismatch or shadow-IT panels. Do not escalate from this panel alone; escalate only if the same process/library pair is suspicious in another detection context.

### 08 Known-malware JA4+JA4S lookup   (Known-bad & reference · `wb_malware.kql`)
**What it detects:** Opt-in matches between observed TLS fingerprints and a static embedded FoxIO `ja4plus-mapping` reference for known malware or C2 tooling.
**Hunt hypothesis:** "Known malware C2 shows up as exact client JA4 plus server JA4S fingerprint pairs, or as distinctive JA4/certificate structures documented in public FoxIO mapping data."
**MITRE ATT&CK:** T1071.001 (Web protocols)
**Reads:** `DeviceNetworkEvents` (`SslConnectionInspected`) — `AdditionalFields.ja4`, `AdditionalFields.ja4s`, `AdditionalFields.server_name`, `AdditionalFields.issuer`, `AdditionalFields.subject`, `DeviceId`, `DeviceName`, `RemoteIP`; rarity-gated: no; known-bad: opt-in
**How it works:** This panel runs only when the workbook's **Known-bad lookup** toggle is **On**. It uses static embedded datatables derived from FoxIO's public `ja4plus-mapping` data, not a live feed or premium feed; families in the embedded mapping include Sliver, IcedID, Cobalt Strike, SoftEther, and Evilginx. Exact `ja4_` + `ja4s_` pair matches are CRITICAL; distinctive single-JA4 and self-signed public C2-class certificate structures are surfaced for corroboration or review.

**Sample query (excerpt):** the detection heart of `wb_malware.kql` (the full query ships in the workbook panel; in the deployed workbook `lookback`/`minRarity` are bound to the **Lookback window** / **Min rarity** dropdowns):
```kql
union pairHits, singleHits, certHits
| summarize Devices = dcount(DeviceId, 4), DeviceNames = make_set(DeviceName, 5), Conns = count(),
            Dests = make_set(coalesce(sni, tostring(RemoteIP)), 5), Issuers = make_set(issuer, 3), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by Family, MatchType, ja4_, ja4s_
| extend Verdict = case(MatchType == "JA4X-approx (cert structure)", "REVIEW - C2-class cert structure (verify)",
                        MatchType == "JA4 (distinctive)" and Family startswith "Evilginx", "HIGH - AiTM JA4 (corroborate sign-in)",
                        "CRITICAL - known malware fingerprint")
| extend Why = case(
    MatchType == "JA4+JA4S pair", strcat("exact client JA4 ", ja4_, " + server JA4S ", ja4s_, " match the ", Family, " known-bad pair in FoxIO ja4plus-mapping (documented C2 client+server)"),
    MatchType == "JA4 (distinctive)", strcat("client JA4 ", ja4_, " is the distinctive ", Family, " fingerprint (FoxIO ja4plus-mapping)"),
    "self-signed cert (issuer = subject, no Organization/Country field) to a public host = C2-class cert structure seen in Sliver/Havoc/Qakbot; verify the issuer")
| project Verdict, Family, Why, MatchType, ja4_, ja4s_, Devices, DeviceNames, Conns, Dests, Issuers, FirstSeen, LastSeen
| sort by Verdict asc, Conns desc
```
**Output columns** —
| Column | What it means |
|---|---|
| `Verdict` | Priority label: known malware fingerprint, AiTM JA4, or C2-class certificate structure. |
| `Family` | Mapped family or class, such as Sliver, IcedID, CobaltStrike, SoftEther VPN, Evilginx, or self-CA C2-class cert. |
| `Why` | Plain-English evidence. For pair hits it states: exact client JA4 X + server JA4S Y match the `<Family>` known-bad pair in FoxIO `ja4plus-mapping`. |
| `MatchType` | `JA4+JA4S pair`, `JA4 (distinctive)`, or `JA4X-approx (cert structure)`. |
| `ja4_` | Observed client JA4 fingerprint. |
| `ja4s_` | Observed server JA4S fingerprint; required for exact pair hits. |
| `Devices` / `DeviceNames` | Distinct device count and sample device names. |
| `Conns` | Matching connection count. |
| `Dests` | Example SNI values or remote IPs. |
| `Issuers` | Example certificate issuer values, used especially for cert-structure review. |
| `FirstSeen` / `LastSeen` | First and last matching observations. |
**Reading this output:** Read `Verdict`, `MatchType`, and `Why` first. A `CRITICAL - known malware fingerprint` row with `MatchType="JA4+JA4S pair"` means the exact client and server TLS fingerprints matched an embedded known-bad pair; that is stronger than a JA4-only collision. The `Why` column carries the reasoning. To validate a hit, click the workbook's **Sources & validation** card, open FoxIO's `ja4plus-mapping.csv` at `https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv`, and search for the exact `ja4_` and `ja4s_` values from the row.
**Verdict / severity bands** —
| Value | Threshold | Means | Action |
|---|---|---|---|
| `CRITICAL - known malware fingerprint` | `MatchType = "JA4+JA4S pair"` for embedded known-bad pair, or other non-review/non-AiTM mapped hit in the query case logic | Observed TLS client+server pair matches public known-bad mapping. | Validate exact values in FoxIO CSV, then escalate to IR immediately. |
| `HIGH - AiTM JA4 (corroborate sign-in)` | `MatchType = "JA4 (distinctive)"` and `Family` starts with Evilginx | Distinctive Evilginx/AiTM client JA4 appeared, but JA4-only matches need corroboration. | Check risky sign-ins, impossible travel, session theft indicators, and identity alerts. |
| `REVIEW - C2-class cert structure (verify)` | Self-signed public cert with issuer = subject and no `O=` or `C=` | Certificate structure resembles C2-class self-CA patterns. | Verify issuer/cert details and correlate with process/destination context. |
**Tunables:** Workbook `Known-bad lookup` toggle → Off skips this opt-in panel, On runs it; `lookback = 30d` → controls observed telemetry window; embedded `malwarePairs` and `ja4single` datatables → static reference values that require workbook/KQL updates when FoxIO mappings change; cert rule `issuer == subject` with no `O=` or `C=` to public IP → controls JA4X-approx review hits.
**False positives:** JA4 library collision, especially Go-based tools → CRITICAL requires exact JA4+JA4S pair, not JA4 alone → validate both values in FoxIO CSV and correlate with host/process. Legitimate self-signed public service → cert-structure rows are REVIEW, not known-bad → verify issuer, owner, and destination before escalation. Static mapping staleness → datatable is not a live feed and fingerprints rotate → use the Sources & validation card and current FoxIO CSV for confirmation.
**Example row:** `Verdict="CRITICAL - known malware fingerprint"; Family="Sliver"; MatchType="JA4+JA4S pair"; ja4_="t13d190900_9dc949149365_97f8aa674fd9"; ja4s_="t130200_1301_a56c5b993250"; Why="exact client JA4 t13d190900_9dc949149365_97f8aa674fd9 + server JA4S t130200_1301_a56c5b993250 match the Sliver known-bad pair in FoxIO ja4plus-mapping (documented C2 client+server)"` → CRITICAL because the exact client/server fingerprint pair matches the embedded Sliver known-bad pair.
**Next step:** For exact JA4+JA4S CRITICAL hits, validate the row against FoxIO `ja4plus-mapping.csv`, then escalate to IR with device names, destinations, first/last seen, and process timeline from related telemetry. For HIGH or REVIEW rows, corroborate before declaring compromise.

## Parameter reference

| Parameter | Default | Allowed values | What it controls / effect on results |
|---|---:|---|---|
| Lookback window | 7d | 7d, 14d, 30d, 60d, 90d | Sets how much history each query scans. Wider windows give you more historical context, but they increase query cost and scale risk on large fleets. |
| Min rarity (focus) | 0.7 | 0.0, 0.5, 0.7, 0.85, 0.95 | Sets the minimum rarity score a JA4 or JA4S TLS fingerprint must meet before the workbook shows it. Higher values show fewer, rarer rows. |
| Section | leads | leads, hunt, corr, inv, ref | Selects which workbook section runs: Top Leads, Hunt, Corroboration, Destination & inventory, or Known-bad & reference. Only the selected section's panels run, one at a time, so the workbook stays fast. |
| Known-bad lookup | off | off, on | Runs the opt-in FoxIO known-malware JA4+JA4S pair lookup. Leave it off for normal hunting; turn it on when you want exact known-malware fingerprint checks. |
| Beacon: min connections | 8 | 4, 8, 12, 16 | Sets the minimum number of repeated call-homes needed before a destination can qualify as a beacon. Lower it to catch low-and-slow command-and-control (C2) callbacks. |
| Beacon: min score | 50 | 40, 50, 60, 70 | Sets the minimum regularity score the beacon panel must see before it surfaces a row. Higher values require more periodic, lower-jitter traffic. |

At fleet scale, start with Lookback window = 7d and Min rarity (focus) = 0.7. If you see too much volume or queries feel slow, raise Min rarity to 0.85 or 0.95 before you widen the lookback window. Widen the lookback only when you need more historical context, because each wider step scans more data and can raise query cost or scale risk.

## Data requirements

| Table | ActionType / filter | Key fields | Used by (panels) | Required or optional |
|---|---|---|---|---|
| DeviceNetworkEvents | ActionType == "SslConnectionInspected" and AdditionalFields has "ja4" | TimeGenerated, DeviceId, DeviceName, RemoteIP, RemotePort, AdditionalFields.ja4, AdditionalFields.ja4s, AdditionalFields.server_name, AdditionalFields.issuer, AdditionalFields.subject, AdditionalFields.curve, AdditionalFields.cipher. AdditionalFields is a STRING, so the KQL parses it with todynamic(). | All panels; this is the core JA4/JA4S TLS-fingerprint telemetry. JA4 is the client TLS fingerprint; JA4S is the server TLS fingerprint. | Required by all panels. |
| DeviceNetworkEvents | ActionType == "ConnectionSuccess" and process fields are populated | InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName or account context when present, InitiatingProcessVersionInfoCompanyName, InitiatingProcessParentFileName, InitiatingProcessSHA1, DeviceId, RemoteIP, RemotePort | Process attribution in triage, mismatch, c2shape, leads, doh, ech, lineage, motw, lots, shadowit, deprecated, impossible, baseline. | Required for panels that tell you which process made the connection; optional for pure TLS-shape panels. |
| SecurityIncident + SecurityAlert / AlertEvidence | Incidents and alerts within the lookback; SecurityAlert entities parsed for device IDs and IP addresses; AlertEvidence uses DeviceId and alert metadata | IncidentNumber, Title, Severity, AlertIds, SystemAlertId, Entities.MdatpDeviceId, Entities.Address, AlertId, DeviceId, Severity, TimeGenerated | Incident-match fidelity in leads; alert bridging in bridge; detonation alert corroboration in detonation. | Optional overall; required for incident, bridge, and detonation corroboration. |
| DeviceFileEvents | FileCreated with FileOriginUrl for mark-of-the-web (MOTW, a web-download marker); FileRenamed, FileModified, FileDeleted, or FileCreated bursts for ransomware staging | TimeGenerated, DeviceId, DeviceName, ActionType, FileName, FolderPath, SHA1, FileOriginUrl, FileOriginReferrerUrl | motw, ransom | Optional overall; required for MOTW and ransomware panels. |
| DeviceProcessEvents / DeviceImageLoadEvents | Process-start lineage within the lookback; image-load telemetry if you extend lineage to loaded libraries | DeviceId, FileName, FolderPath, ProcessCommandLine, SHA1, ProcessVersionInfoCompanyName, InitiatingProcessFileName, InitiatingProcessParentFileName, image/DLL name and path when present | lineage | Optional overall; required for lineage enrichment. |
| DeviceLogonEvents / IdentityInfo | Recent logons with AccountName and DeviceId; IdentityInfo role or privilege fields when available | DeviceId, DeviceName, AccountName, AccountDomain, AccountUpn or UPN prefix, AssignedRoles or privileged-account indicators | privja4, aitm, phish, cloudexfil | Optional overall; required for identity-to-device correlation panels. |
| SigninLogs / AADSignInEvents | Risky Entra sign-ins, especially RiskLevelDuringSignIn in high or medium | UserPrincipalName, IPAddress, RiskLevelDuringSignIn, RiskState, Location, AppDisplayName, TimeGenerated | aitm | Optional overall; required for adversary-in-the-middle (AiTM) sign-in correlation. |
| EmailEvents | Delivered phish or malware mail: ThreatTypes has Phish or Malware and DeliveryAction != Blocked | RecipientEmailAddress, Subject, ThreatTypes, DetectionMethods, SenderFromAddress, SenderMailFromDomain, NetworkMessageId, TimeGenerated | phish | Optional overall; required for phish-to-implant correlation. |
| CloudAppEvents | Upload, download, export, share, sync, or anonymous-proxy cloud activity within the lookback | Application, ActivityType, ActionType, AccountDisplayName, AccountObjectId, IPAddress, ObjectName, IsAnonymousProxy, CountryCode, TimeGenerated | cloudexfil | Optional overall; required for cloud-exfiltration corroboration. |
| DeviceInfo | Latest device metadata and public IP mapping within the lookback | DeviceId, DeviceName, PublicIP, OSPlatform, TimeGenerated | bridge, cloudexfil, hygiene | Optional overall; required when a panel maps device to public IP or operating system. |

A section with no matching data returns no rows — that is not an error; it means either a clean estate or that telemetry isn't streaming.

## Troubleshooting

### Panels return no rows

**Most likely cause:** JA4 telemetry is not streaming, the estate is clean for the selected hunt, or the Lookback window is too short.

**Check:** Start by confirming whether inspected TLS connection telemetry exists in the workspace.

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d) and ActionType == "SslConnectionInspected"
| count
```

If the count is `0`, JA4 telemetry is not streaming. If the count is greater than `0`, the workbook may simply have no matches at the current thresholds.

**Fix:** Confirm the Defender XDR `DeviceNetworkEvents` connector is streaming to Microsoft Sentinel. If telemetry exists, widen Lookback first, then lower Min rarity to `0.0` to confirm the workbook can return broad results.

### Query partially succeeded / E_RUNAWAY_QUERY (80DA0001): 'join' or 'summarize' operator has exceeded the memory budget (5368709120)

**Most likely cause:** Kusto hit the 5 GB per-operator memory limit while scanning, joining, or summarizing fleet-scale `DeviceNetworkEvents` data across the production tenant.

**Check:** First confirm the deployed workbook uses the current fleet-scale query shape. Open the panel KQL and look for the base event scan being filtered with a small key set, for example `where JA4 in (RareJa4Set)` or `where JA4S in (RareJa4SSet)`.

The structural fix that shipped is the `where col in (smallKeySet)` broadcast-filter pattern. The workbook builds a small rare-key set, broadcasts that set, and streams the firehose through the filter, so the firehose is never shuffled.

Do not replace this with `join kind=leftsemi hint.strategy=broadcast <smallSet>` over the firehose. In Kusto, `hint.strategy=broadcast` broadcasts the left side of the join. If the left side is the huge `DeviceNetworkEvents` firehose, Kusto ignores the hint or shuffles the firehose, which can trigger the same 5 GB failure.

**Fix:** As an immediate analyst mitigation, set Lookback to `7d` and raise Min rarity to shrink the scan. The deployed workbook already uses the correct broadcast-filter pattern, so this error should not recur on a current deployment. If it does recur, the deployment is stale; redeploy the latest workbook.

### The Min rarity slider seems to do nothing / removes everything

**Most likely cause:** The slider direction is being read backwards, or the selected data sits on one side of the rarity threshold. Raising Min rarity keeps only rarer fingerprints, so it returns fewer rows. `0.0` shows everything.

**Check:** Use the slider as a quick before/after test. Set Min rarity to `0.0`, rerun the section, then raise it one step at a time to `0.7`, `0.85`, or `0.95` and compare row counts.

If `0.0` returns rows but higher values remove them, the fingerprints are not rare enough for the selected threshold. If every setting returns about the same rows, the visible rows are already above the threshold.

**Fix:** Use `0.0` for validation and broad inventory, `0.7` for normal triage, and `0.85` or `0.95` when you want only very rare fingerprints.

### The beaconing panel never scores above 50 / shows nothing

**Most likely cause:** The default beacon thresholds are too strict for low-and-slow or jittered traffic. BeaconScore is based on interval regularity: coefficient of variation (CV) and jitter can push scores below `50`, even when the pattern is worth reviewing. The current workbook also surfaces a low-and-slow Pattern for slower call-home behavior.

**Check:** Relax the beacon thresholds before deciding there is no beaconing. Set Beacon min connections from `8` to `4`, set Beacon min score from `50` to `40`, rerun the panel, and review the Pattern value for `regular`, `jittered`, or `low-and-slow`.

**Fix:** Hunt with `4` connections and score `40` when looking for weak or low-and-slow signals, then pivot into process, host, and destination evidence. Return to `8` and `50` after triage to reduce noise.

### Known-bad lookup shows no matches

**Most likely cause:** The known-bad lookup is off, or the static reference table has no match for the selected fingerprints.

**Check:** First confirm the opt-in reference lookup is enabled. Set Known-bad lookup to `On`, rerun the reference section, and check whether the FoxIO `ja4plus-mapping` table returns matches.

**Fix:** Treat matches as high-priority leads, not as the only way to identify bad traffic. The lookup uses a static FoxIO `ja4plus-mapping` table, and fingerprints rotate roughly yearly, so no match is not proof that a fingerprint is safe.

### A corroboration/identity/email panel is empty but the hunt panels have results

**Most likely cause:** The hunt panels can return results from `DeviceNetworkEvents`, while the empty panel needs a second data source that may not be streaming to the workspace.

**Check:** Check the supporting tables for recent rows before troubleshooting the workbook logic.

```kql
union isfuzzy=true
    (DeviceFileEvents | where TimeGenerated > ago(7d) | summarize Rows=count() | extend Source="DeviceFileEvents"),
    (SigninLogs | where TimeGenerated > ago(7d) | summarize Rows=count() | extend Source="SigninLogs"),
    (EmailEvents | where TimeGenerated > ago(7d) | summarize Rows=count() | extend Source="EmailEvents"),
    (IdentityInfo | where TimeGenerated > ago(7d) | summarize Rows=count() | extend Source="IdentityInfo"),
    (CloudAppEvents | where TimeGenerated > ago(7d) | summarize Rows=count() | extend Source="CloudAppEvents")
| project Source, Rows
```

If the relevant table is missing or returns `0` rows, that corroboration panel has no data to enrich the JA4 hunt results.

**Fix:** Connect or repair ingestion for the missing source: `DeviceFileEvents`, `SigninLogs`, `EmailEvents`, `IdentityInfo`, or `CloudAppEvents`. Until that source is streaming, continue triage from the hunt panels and document the missing corroboration source in the case notes.

## Glossary

| Term | Definition | Why it matters here |
|---|---|---|
| a-section | The first JA4 section describes the visible TLS client shape: protocol, TLS version, SNI presence, cipher count, extension count, and ALPN. It is the quick read on what kind of TLS handshake the client attempted. | Panels use it to spot odd shapes such as legacy TLS, no SNI, no ALPN, too few ciphers, or too many ciphers before looking at hashes. |
| AiTM | Adversary-in-the-middle is phishing or proxying that places an attacker between the user and a real login service to steal sessions or tokens. Evilginx and Modlishka are common examples. | The AiTM panel looks for rare or non-browser JA4 callouts near risky Entra sign-ins, which can indicate session theft rather than normal browsing. |
| ALPN | Application-Layer Protocol Negotiation is the TLS field where a client offers application protocols such as HTTP/2 (`h2`) or HTTP/1.1 (`h1`). Modern browsers usually send it. | Missing ALPN on public TLS, especially from a LOLBIN or TLS 1.2 shape, is a C2 clue because real browsers usually negotiate ALPN. |
| BeaconScore | BeaconScore is a 0-100 regularity score for repeated TLS call-homes, where higher means more periodic. The workbook uses both CV-based and IQR-based regularity so jittered-but-periodic traffic still appears. | Regular rare JA4 traffic to the same destination is a classic C2 beaconing pattern, so high BeaconScore rows deserve early triage. |
| b-section | The b-section is the 12-character middle JA4 hash that this workbook uses as a stable TLS-library identifier. Common mapped values identify libraries such as Chromium, Firefox, Python, Go, WinINET, WinHTTP, and SoftEther. | It lets you compare the TLS library implied by JA4 with the process that supposedly made the connection. |
| b-section library mismatch | A b-section library mismatch occurs when the JA4 library hint contradicts the initiating process, such as a Chromium TLS library from a non-browser or Go/Python TLS from a LOLBIN. | This is high-signal because injection, uTLS parroting, loaders, and PUPs often borrow or imitate a TLS stack that does not match their process. |
| c-section | The c-section is the final 12-character JA4 hash and captures another stable part of the client TLS behavior. Some C2 tools expose distinctive c-section values, such as the Cobalt Strike value `16bbda4055b2`. | The C2 tradecraft panel can flag a distinctive client c-section even when the destination or IP changes. |
| ConnectionSuccess | ConnectionSuccess is a Microsoft Defender DeviceNetworkEvents action for a successful network connection. It includes fields such as the initiating process name and folder path. | The workbook uses it to attribute a JA4 flow to a process, which is required for LOLBIN, mismatch, LOTS, and many escalation decisions. |
| CV (coefficient of variation) | CV is the standard deviation divided by the mean of the time gaps between repeated connections. Lower CV means the gaps are steadier and more beacon-like. | A low CV supports a beaconing verdict; a high CV usually points to normal irregular user or application traffic. |
| ECH | Encrypted Client Hello hides the real SNI by encrypting the inner TLS ClientHello. Defenders may only see no cleartext SNI or an ECH bootstrap hostname. | Browser ECH can be normal, but ECH or no-SNI browser-like traffic from a non-browser or LOLBIN can hide C2 destinations. |
| GREASE | GREASE means Generate Random Extensions And Sustain Extensibility, a TLS practice where clients send reserved placeholder values so the ecosystem keeps tolerating new values. JA4-aware analysis normalizes these placeholders instead of treating them as malware by default. | It prevents false positives from normal browser behavior and helps identify synthetic or malformed TLS clients that mishandle modern TLS conventions. |
| JA4 | JA4 is a TLS client fingerprint built from the ClientHello, the first TLS message a client sends. It summarizes the client TLS shape in a way that is more useful for hunting than a single IP address. | It lets Tier-1 analysts recognize the same client tool or implant across hosts, destinations, and IP rotation. |
| JA4_ac | JA4_ac is a reduced JA4 made from the a-section and c-section while dropping the cipher-hash section. It groups related full JA4 values when a client changes ciphers but keeps the same broader behavior. | The workbook uses it to catch cipher-cycling actors that generate many full JA4s to evade exact fingerprint matching. |
| JA4S | JA4S is the server-side TLS fingerprint built from the ServerHello, the server reply in a TLS handshake. It describes how the destination server responds. | Pairing JA4 with JA4S improves known-bad matching and helps separate real C2 infrastructure from benign services that share a client JA4. |
| known-bad / JA4X | Known-bad means a public FoxIO fingerprint already associated with named malware or tooling, usually an exact JA4 plus JA4S pair. JA4X is FoxIO's certificate-fingerprint family; this workbook approximates C2-class JA4X behavior with suspicious self-signed public certificates. | Exact known-bad hits are critical leads, while JA4X-style certificate structure gives a reviewable clue when the client fingerprint is not enough. |
| LOLBIN | A LOLBIN is a legitimate built-in or trusted binary that attackers abuse, such as `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, or script hosts. The term comes from living off the land. | A LOLBIN should rarely originate public TLS on its own, so rare JA4 or no-ALPN TLS from one is a strong loader or injection signal. |
| LOTS | Living off trusted sites means using trusted cloud, CDN, SaaS, or collaboration domains to carry malicious traffic. The destination looks trusted, but the client behavior may not. | The LOTS panel hunts the paradox of a rare JA4 from a non-browser or LOLBIN reaching trusted services such as GitHub, Discord, Telegram, Azure, or Cloudflare. |
| malleable C2 | Malleable C2 is C2 traffic whose operator can change visible HTTP profile details such as paths, headers, or timing. Some underlying TLS behavior, such as WinINET/WinHTTP ClientHello shape, may remain stable. | The workbook looks below the malleable layer for TLS 1.2, no ALPN, Cobalt Strike c-section, and Cobalt Strike JA4S signals. |
| MatchFidelity | MatchFidelity is a 0-100 score for how tightly a rare fingerprint ties to an incident. It combines match specificity, temporal decay, rarity, and incident severity. | It helps you prioritize whether a JA4 seen near an alert is probably related or only a weak shared-IP coincidence. |
| Pyramid of Pain | The Pyramid of Pain is David Bianco's model for how hard different indicators are for an attacker to change. IP addresses are easy to rotate; behaviors and tool fingerprints are harder. | It explains why this workbook emphasizes JA4 and JA4S over destination IPs when hunting repeatable attacker tooling. |
| Rarity (R) | Rarity is a 0-1 inverse-prevalence score where 1 means near-unique in the estate. The workbook computes R as the smaller of host rarity and connection rarity, so a fingerprint is rare only when few devices and few connections use it. | The Min rarity selector uses R to suppress common enterprise software and focus Tier-1 attention on unusual clients. |
| Rconn | Rconn is the connection-count rarity component: fingerprints with few total connections score higher. A fingerprint that appears in many connections becomes less rare even if few hosts use it. | It keeps noisy recurring software from looking rare just because it appears on a small number of devices. |
| Rhost | Rhost is the host-count rarity component: fingerprints seen on few endpoints score higher. A fingerprint seen across many devices becomes less rare. | It helps separate targeted or novel tooling from normal software deployed across the estate. |
| SNI | Server Name Indication is the hostname a TLS client normally sends in the ClientHello so the server can choose the right certificate. It can be absent, an IP literal, or hidden by ECH. | No SNI, SNI as a raw IP, or ECH-hidden SNI on public traffic can indicate automation, evasion, or C2. |
| SslConnectionInspected | SslConnectionInspected is a Microsoft Defender DeviceNetworkEvents action that records inspected TLS handshake metadata such as JA4, JA4S, SNI, certificate fields, and AdditionalFields. It is metadata inspection, not content decryption. | Most workbook panels start here; if this action or JA4 values are missing, JA4 hunting panels return no rows. |
| SuspicionScore | SuspicionScore is a 0-100 weighted score that adds suspicious signals such as LOLBIN, legacy TLS, self-signed public certs, no extensions, no SNI, user-path processes, and no ALPN, then subtracts benign discounts. | It turns several weak clues into a single triage priority so Tier-1 analysts know which rare JA4 rows to read first. |

## Changelog and sources

| Version | Change | Maintenance note |
|---|---|---|
| v1.0 (2026-06) | Initial guide. Covers ~30 detection panels across 5 sections; reflects the self-explanatory evidence wording and the in-result Sources & validation card. | The FoxIO malware-pair table is a static embedded datatable, not a live feed; re-validate tuned thresholds when FoxIO updates. |

### Sources & validation

Every claim in this guide is grounded in a public, citable source. Use these links to validate workbook verdicts yourself:

- **JA4 / JA4S structure, the b-section TLS-library map, and all known-bad fingerprints** (Cobalt Strike, Sliver, IcedID, SoftEther, Evilginx) come from FoxIO's public JA4+ project and its `ja4plus-mapping.csv`: [FoxIO JA4+ project](https://github.com/FoxIO-LLC/ja4) and [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv). To validate a known fingerprint verdict, search that CSV for the exact `ja4` or `ja4s` in the row; for example, Cobalt Strike v4.9.1 beacon = `t12i190700_d83cc789557e_16bbda4055b2` / JA4S `t120300_c030_52d195ce1d92`, and the c-section `16bbda4055b2` is what the C2 panel flags.
- **"A LOLBIN should not originate TLS"** comes from the LOLBAS project: [LOLBAS](https://lolbas-project.github.io/).
- **MITRE ATT&CK technique mappings** come from [MITRE ATT&CK](https://attack.mitre.org/).
- **Why a JA4 outranks an IP** comes from David Bianco's Pyramid of Pain: [The Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html).
- **The incident-match temporal decay** follows the indicator-aging concept in MISP decaying models: [Decaying of indicators](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html/).
- **The data source schema** for `SslConnectionInspected`, `AdditionalFields`, and `ConnectionSuccess` comes from Microsoft Learn: [DeviceNetworkEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table).
