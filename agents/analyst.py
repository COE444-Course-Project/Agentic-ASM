"""Rule-based triage draft. Proposals are not independently verified findings."""
from core import state_store as store
from core.template_catalog import TEMPLATES

PROPOSALS = {
    "lab-bola": "Enforce object ownership for this lab collection using its policy overlay",
    "bola-book": "Enforce authenticated-user ownership before returning a book",
    "bola-password": "Require account ownership before changing a password",
    "mass-assignment": "Allowlist registration fields and assign roles server-side",
    "debug-exposure": "Disable the debug endpoint and remove password disclosure",
    "forged-jwt": "Rotate the signing secret and invalidate existing tokens",
    "user-enumeration": "Return a uniform authentication failure response",
    "sql-injection": "Use parameterized database queries for user lookup",
    "unauth-book-listing": "Review whether the book catalog should require authentication",
}


def triage(findings: list[dict]) -> list[dict]:
    plans = []
    for finding in findings:
        module = finding.get("module_id", finding["id"])
        proposal = PROPOSALS.get(module)
        template = finding.get("template")
        if module == f"lab-{template}" and template in TEMPLATES:
            proposal = f"Enforce {template} authorization on this scenario operation"
        plans.append({
            "finding_id": finding["id"], "target": finding["target"],
            "observed_round": finding.get("last_round"),
            "module_id": module, "collection": finding.get("collection"), "template": template,
            "proposal": proposal or "Manual investigation required: no remediation recipe",
            "status": "proposed" if proposal else "needs_review",
            "verification": ["Replay the original exploit and confirm it is blocked",
                             "Confirm legitimate owner workflows still succeed"],
        })
    store.log_event("analyst", f"drafted {len(plans)} remediation plans; evidence needs verification")
    return plans
