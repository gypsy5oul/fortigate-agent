# Lab incidents for the golden set (placeholder)

Plan C2.2 asks for two real incidents from the lab next to the scripted cases in `../golden/`. They
cannot be produced outside the lab, so this directory is empty until an operator exports them.

1. Pick two shadow-mode incidents from the lab database that an analyst has reviewed (one non-blocked
   exploit, one blocked or mixed), for example from `scripts/shadow_report.py` output.
2. Export each one, redacted, in ADK's EvalSet format:

   ```bash
   DATABASE_URL=postgresql://<user>:<password>@<db-host>:5432/<db> \
     python scripts/export_golden_incident.py <incident_id> <revision> > evals/lab/<name>.test.json
   ```

   The script reads the packet the agent saw (the ADK session `<incident_id>:<revision>`), replaces
   every IP address with a documentation-range placeholder, every URL host with `redacted.example`
   and the incident id with `INC-LAB-<hash>`, takes the revision's committed assessment as the
   reference answer, and refuses to print anything that still contains a non-documentation address.
3. Review the file by hand before committing it: the reference answer must be what an analyst would
   sign off, and nothing in it may identify the site. Then run the lab evaluation (README section 6).

`tests/agent/test_golden_eval_lab.py` picks up every `*.test.json` here automatically.
