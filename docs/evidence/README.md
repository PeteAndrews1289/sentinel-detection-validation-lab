# Evidence gallery

Selected public review copies. Click an image to inspect it at full resolution. Crops/redactions are documented in [image-provenance.json](image-provenance.json). Raw originals remain private.

## All six detectors enabled; diagnostic disabled

![All six detectors enabled; diagnostic disabled](../images/rules-enabled.png)

## DVL-001: alert search using the full source EventKey

![DVL-001: alert search using the full source EventKey](../images/dvl001-eventkey-alerts.png)

## DVL-002: exact EventKey matches

![DVL-002: exact EventKey matches](../images/dvl002-exact-key-alerts.png)

## DVL-003: scheduled alert; historical run attribution is limited

![DVL-003: scheduled alert; historical run attribution is limited](../images/dvl003-exact-key-alert.png)

This is genuine scheduled alert evidence; the historical matching run lacks a completed manifest. It is not paired with the separate development account.

## DVL-004: two exact-key alerts for one registry write

![DVL-004: two exact-key alerts for one registry write](../images/dvl004-exact-key-summary.png)

## DVL-005: hash-only control is present and evaluates false

![DVL-005: hash-only control is present and evaluates false](../images/dvl005-hash-only-control.png)

## DVL-005: before correction, EventID is present but EventKey is absent

![DVL-005: before correction, EventID is present but EventKey is absent](../images/dvl005-before-mapping-fix.png)

## DVL-005: new test alerts include the correct EventKey

![DVL-005: new test alerts include the correct EventKey](../images/dvl005-after-mapping-fix.png)

## DVL-006: source pair and combined key

![DVL-006: source pair and combined key](../images/dvl006-correlated-source-pair.png)

## DVL-006: both source keys and the combined key match the alert

![DVL-006: both source keys and the combined key match the alert](../images/dvl006-three-keys-match.png)

## DVL-006: alert associated with incident; status remains New

![DVL-006: alert associated with incident; status remains New](../images/dvl006-incident-link.png)

The incident is associated with the alert and is shown as **New**. This is not evidence of investigation closure.
