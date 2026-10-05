# Validation record and boundaries

This page summarizes the supplied private archive and the offline review. It does not represent a new cloud test campaign.

## Recorded results

| Check | Result |
|---|---:|
| Rules with positive alert evidence | 6 |
| Completed manifests | 23 |
| Distinct case types | 12 |
| Completed manifests reporting execution and cleanup success | 23 |
| Per-run evidence hashes checked / matched | 137 / 137 |
| Local XML exports parsed | 38 |
| Completed runs with declared, run-matched local telemetry in their exports | 20 / 23 |
| Original validation-tool unit tests | 16 passed offline |

The 23 manifests include repeated tests. They are not 23 different scenarios. The local tests exercise Python fixtures, not live Sentinel or Windows behavior. The public release also re-ran these unit tests; its captured output is in [checks](../checks/unit-tests.txt).

## Evidence coverage by detector

| Rule | Positive alert evidence | Query-level control | Remaining qualification |
|---|---|---|---|
| DVL-001 | Source EventKey-filtered alerts | Plain PowerShell excluded | Scheduled negative screenshot was preliminary |
| DVL-002 | Task registration, creation event, exact-key alerts, incident association | Task lookup excluded | Local event-1 export supplied the creation evidence absent from one screenshot |
| DVL-003 | Scheduled alerts with exact-key check | Users-group addition excluded | Historical scheduled-run attribution is incomplete |
| DVL-004 | Registry source evidence and exact-key alert summary | Ordinary setting excluded | Health/search delay cause was not established |
| DVL-005 | Decoding read-back and exact-key alerts after mapping fix | File hashing excluded | Before/after alert enrichment is retained |
| DVL-006 | Two source keys + composite key verified in alert, incident association | Creation-only example | Initial control observation had not elapsed |

## Historical gaps retained in the private review

Three early completed runs have local export-error files instead of all required XML; later representative runs include the required telemetry. One additional historical Administrator trial contains only a partial transcript and no completed manifest or cleanup confirmation. It is not counted among the 23 completed runs.

The harness records `ended_utc` before its finally-block cleanup has fully completed. Do not treat it as an exact cleanup-completion timestamp. Manifest success and matching hashes are not a new live audit of the VM.

## What is deliberately not claimed

No population false-positive rate, zero-false-positive claim, completed scheduled negative campaign, production deployment readiness, configured entity enrichment, duplicate-alert reduction or incident closure. No requirement to perform another campaign was added for the interview edition.

## Code and query provenance

The deployed queries are exact strings from the final rule export. Starter/helper queries under `lab/queries` are retained separately because the read-only validator selects those paths. They are not silently asserted to be byte-identical to the deployed versions. `lab/config/detections.json` is a starter catalog, not the authority for deployed severity or technique metadata.

The public workflow is newly configured to run only the offline unit tests. A successful workflow badge or live cloud validation result is not claimed before an actual run. [Source hashes](source-provenance.json)
