# Architecture and evidence design

## Collection paths used in the build

The endpoint was an Azure-hosted Windows Server 2022 VM named `vm-dvl-win`. Azure Monitor Agent delivered Sysmon Operational records through a Windows-event DCR to `Event`. Windows Security auditing delivered account and membership events through the Sentinel Security Events connector to `SecurityEvent`. `law-dvl-lab` was the shared workspace.

The supplied endpoint configuration is [Sysmon XML](../lab/config/sysmon-dvl.xml). [DCR XPath notes](../lab/config/dcr-xpaths.txt) identify the intended filters: Sysmon 1, 11, 13 and 16; Security 4720, 4726, 4732 and 4733. These notes are not an exported cloud DCR or a complete infrastructure deployment.

## What each stage proves

| Stage | Evidence | What it does not establish alone |
|---|---|---|
| Scenario | Run manifest, output read-back | Logging, ingestion or alerting |
| Endpoint logging | Run-matched XML record | Azure delivery |
| Ingestion | Specific source row in the workspace | Detection match |
| Query | The actual query result for the source record | Automatic alert creation |
| Alert | Source EventKey in custom details | Incident investigation/closure |
| Incident | Alert-ID association | Maliciousness or completed response |

## Event keys

The Sysmon key is SHA-256 of the concatenation of `Computer`, `EventID`, `TimeGenerated` and `EventData`, separated by `|`. The account-event key uses `Computer`, event ID, timestamp, normalized account/group SID, `MemberSid` and acting account.

DVL-006 computes a composite key from `CreatedKey + "|" + AddedKey`. Those three keys were verified in the observed alert. This binds the review to the same collected records, not to another alert with the same title. It is not independent proof of the endpoint's authenticity. Because the key includes stored values, differences in normalization/serialization can alter it.

## Query and time semantics

The deployed baseline queries use a rolling 30-minute source window and run every 5 minutes. DVL-006 separately requires `AddedAt >= CreatedAt` and `AddedAt <= CreatedAt + 10m`. It does not wait ten minutes to detect a completed pair. Both sources must fit the shared source window in this version; late-arrival and window-boundary behavior has not been exhaustively validated.

An event timestamp, ingestion timestamp, alert timestamp and the moment an alert first appears in a search are different measurements. One registry sample showed about 20m50s between recorded source and ingestion metadata. No unsupported root cause is assigned to that delay.

## Actual baseline configuration

[Template](../config/sentinel-rules.template.json) properties are preserved from the export, including empty descriptions and unset entity mappings. Hostnames/SIDs in custom details are not represented as configured entity enrichment. Duplicate alerts are visible in the gallery; reducing them is outside this completed interview edition.
