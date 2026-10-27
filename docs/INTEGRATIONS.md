# Read-only integrations

This share edition retains the existing collection, pagination and completeness
logic. Its deployment-specific authentication has been replaced by explicit
process environment inputs. No credential file, home-directory configuration,
company endpoint, or source snapshot is included. Only synthetic and mocked
integration tests have been run on this edition; live access is **not verified**.

The default demonstration uses snapshots and requires no credentials or network.
Live collection is a separate, explicit command and requires authorization for
the selected sources. Do not use real credentials for a demonstration.

| Source | Process environment | Scope |
| --- | --- | --- |
| Jira Server/DC REST v2 | `JIRA_URL`, `JIRA_TOKEN` (Bearer PAT) | `jira_project`, `sample_issues` |
| Dependency-Track | `DT_API_KEY` | `dt_base`, explicit `dt_projects` UUID list |
| Salesforce REST v58.0 | `SF_INSTANCE_URL`, `SF_ACCESS_TOKEN` | `sf_owner`, optional `sf_explicit_cases` |
| Confluence Server/DC (optional) | `CONFLUENCE_URL`, `CONFLUENCE_TOKEN` | `weekly_page` numeric ID |
| CISA KEV | None | Fixed public catalog endpoint |

URLs must use HTTPS and contain no embedded username, password, query or fragment.
Jira, DT and Confluence may have a context path. Salesforce requires an instance
origin. The collector uses the system TLS trust store and refuses redirects.
No TLS-verification bypass is provided. All business requests are GET-only.

Salesforce authentication is intentionally external to this package: provision a
scoped access token through your approved mechanism and pass it through the
process environment. This package does not create an OAuth application, store a
password, refresh tokens, or perform SOAP login. Expired/invalid session responses
remain failures; they are never counted as zero new messages. Obtain a new token
outside the package before explicitly retrying Salesforce.

Missing environment settings produce `ConfigurationUnavailable` with the name of
the missing variable, never its value. If `weekly_page` is absent or null,
Confluence is `NOT_CONFIGURED`; the local generic Weekly template remains usable.

Copy `scripts/psirt_ops/scope.example.json` to an ignored local configuration file,
set the authorized IDs and date window, and configure credentials outside Git.
An explicit `--scope` is required for live collection. For example, **after**
configuration and authorization:

```bash
python3 scripts/run_psirt_ops.py --mode live \
  --scope local-config/scope.json --output-dir outputs/authorized-live
```

The example values are invalid placeholders. A snapshot replay root cannot be
reused for live data. A new run preserves previous reports, and incomplete
pagination stays `PARTIAL` with observed records retained. Findings, distinct CVEs,
DT projects and mapped products are separate concepts; none is a repair decision.

This edition does not read deployment-specific background notes. Add local
review records through the workbench; keep organization data outside version
control. No live call, company-system change or message transmission was made
while preparing this package.
