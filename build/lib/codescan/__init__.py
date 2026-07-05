"""codescan: enterprise code-scanning pipeline.

Bitbucket (repo inventory) + Snyk + Xray (scanners)
  -> normalize -> deduplicate -> enrich (KEV/EPSS/reachability)
  -> AI exploitability & vulnerability chaining
  -> composite risk scoring -> validation states
  -> ServiceNow Vulnerability Response export.
"""

__version__ = "0.1.0"
