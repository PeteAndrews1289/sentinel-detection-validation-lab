# Reproduction guide

## Scope and prerequisites

The repository preserves the tested rule queries and the supplied current harness. It is not one-click infrastructure-as-code. Read the PowerShell scripts before running them and use only an authorized disposable **Windows Server 2022** lab VM, 64-bit **Windows PowerShell 5.1** with administrator rights, and a Sentinel-enabled workspace.

The original build used `C:\DVL\kit` for the kit, `C:\DVL\runs` for private run evidence, and `C:\DVL\baseline` for the audit-policy backup. Copy the **contents of `lab/`** into `C:\DVL\kit` on the VM; do not copy the repository's public images into those runtime folders.

The host filter in the deployed queries is `vm-dvl-win`. Change it deliberately for a different isolated lab, and keep the query's rolling lookback separate from any fixed-time evidence inspection.

## Endpoint and collection

Run `windows/Initialize-Lab.ps1 -AcknowledgeLabOnly` in the VM to back up audit policy and enable the two selected account/group audit categories. Install Microsoft's Sysmon separately after checking its signature, using the supplied `config/sysmon-dvl.xml`.

Configure the two AMA collection paths described in [architecture](architecture.md) and [DCR XPath notes](../lab/config/dcr-xpaths.txt). Confirm local source events and actual ingestion before assuming a missing alert is a detector failure. Microsoft binaries, agent packages and cloud credentials are not redistributed here.

The public rule template targets an existing workspace. Review it before importing or deploying; the exported baseline contains enabled rules. There are no automatic Azure-deployment steps in CI or in the repository-publishing script.

## Controlled scenarios

The harness accepts these 12 case IDs:

| Positive | Control |
|---|---|
| `ps_positive` | `ps_negative` |
| `task_positive` | `task_negative` |
| `admin_positive` | `admin_negative` |
| `runkey_positive` | `runkey_negative` |
| `decode_positive` | `decode_negative` |
| `chain_positive` | `chain_negative` |

Example, **inside the disposable Windows VM only**:

```powershell
& 'C:\DVL\kit\windows\Invoke-LabCase.ps1' -Case decode_positive -AcknowledgeLabOnly -PauseForScreenshot
```

The harness generates a run identifier, records expected rules and required telemetry, verifies selected outcomes, attempts cleanup, then preserves private evidence. When paused, capture the relevant event before pressing Enter. A task/Run-key value may exist during the pause; do not sign out, reboot or manually execute it. The task and Run-key action is deliberately harmless, but the registration itself changes the endpoint.

Accounts are created disabled with generated passwords. Privileged-group scenarios temporarily add those disabled accounts to local Administrators. Do not run this harness on personal, university or employer-managed endpoints outside your explicitly authorized lab.

## Offline Python tests

From the repository root:

```bash
cd lab
python3 -m unittest discover -s tests -v
```

No Azure dependencies or credentials are required for those tests.

## Optional read-only live validator

`lab/tools/validate_run.py` is included with its original helper-query layout. It is read-only against Azure but requires your own Azure CLI authentication, workspace access, SDK dependencies and a real run manifest. Install its dependencies in a virtual environment only if you choose to use this optional tool.

Its source and unit tests are **not** evidence that a complete automated cloud campaign was run. Its helper queries may differ from the deployed query copies. Preserve every output directory and inspect partial-query failures and missing telemetry. Negative results intentionally require manual scheduled-alert review.

## End-of-session care

Complete paused tests, inspect `cleanup_ok`, and preserve run files privately before shutting down or deleting anything. Missing cleanup evidence is not proof that cleanup occurred. Azure resources can incur costs while present; this repository does not configure an automatic spending cap.
