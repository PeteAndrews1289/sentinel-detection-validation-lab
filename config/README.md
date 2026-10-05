# Sentinel configuration

`sentinel-rules.template.json` is derived from the six-rule export from the lab. Its query strings and **all rule properties remain unchanged**. Only exported resource identity fields were generalized: each rule name uses a deterministic ARM `guid()` expression tied to the destination resource group, workspace and rule ID; historical resource `id` fields were removed.

The `workspace` parameter is the name of an **existing** Log Analytics workspace with Sentinel enabled. This template does not create a VM, workspace, agent, DCR or network. Import/deployment can create enabled, billable analytics rules and may duplicate existing rules if their IDs differ. Review it before any deployment; the publishing script never deploys Azure resources.

The recorded baseline is 5-minute evaluation frequency, 30-minute source lookback, threshold greater than zero, alert per result, suppression disabled, and incident creation enabled. Entity mappings remain unset and rule descriptions remain empty, as they were in the supplied export. This public release does not retroactively improve those deployed settings.

`lab/config/dcr-xpaths.txt` records the intended collection filters. It is not a complete exported DCR resource. `lab/config/sysmon-dvl.xml` is the actual supplied endpoint configuration snapshot.
