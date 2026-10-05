# Public release, privacy and provenance

This repository is a **curated public derivative** of Pete Andrews's private interview bundle. It does not contain the entire private bundle.

## Omitted

Raw VM run directories, full Windows event exports, transcripts, audit-policy backups, incomplete private trials, screen thumbnails from the private gallery, exported public RDP addresses, emails, subscription/workspace identifiers and full Azure incident URLs are not intentionally included.

## Included

The current lab scripts, helper/tool unit tests, deployed KQL strings, Sysmon configuration snapshot, intended DCR filters, a reusable rule-template derivative, documentation and 11 selected screenshot review copies.

Screenshots are cropped or visibly redacted, not recreated results. Machine-specific account SIDs and cloud resource URLs are withheld where those fields occur in the selected excerpts. Result values, source-event hashes, test run IDs, alert IDs and the lab's intentionally disposable host/account names are retained where necessary to follow the evidence. Original-resolution private originals are preserved outside the repository.

[Image provenance](evidence/image-provenance.json) records the original/private hash, public hash, crop coordinates and redaction regions. [Source provenance](source-provenance.json) records copied code/query hashes. A reviewed public screenshot is not the byte-identical original and is not described as one.

The reusable rule template changes only resource identity expressions, not detection conditions or rule properties. The actual deployed queries remain separately available.

## Implementation provenance

Pete performed the lab setup, scenario executions, query checks, configuration and evidence capture described here. Scripts, queries, troubleshooting and documentation were developed with AI assistance during the project. The repository does not imply that every line was independently written without assistance. The useful claims are the demonstrated system behavior and the ability to explain its implementation and limitations.

## Reuse and license

No additional open-source license grant has been selected for this publication package. Third-party platforms and tools retain their respective rights; Microsoft binaries are not included. Repository visibility is not an invitation to run the test scenarios outside authorized systems.

## Publication checks

The release manifest and the publisher's explicit file allowlist prevent accidental inclusion of added private files during initial publication. They do not replace a full secrets audit. Review any future additions, especially screenshots and logs. The publishing script does not access or upload the user's Downloads private-portfolio folder.
