# Incident Response Basics

Use this document as a starting reference, not as a substitute for an organization's approved incident-response plan.

## Initial triage
- Validate the alert against original source logs and nearby events.
- Establish the event timestamp, affected asset, account, and likely scope.
- Separate observed facts from assumptions and hypotheses.
- Preserve relevant logs and evidence using the organization's evidence-handling procedure.
- Record the source, time, analyst, and reasoning for each decision.

## Possible account compromise
- Review authentication logs, MFA events, session history, and recent account changes.
- Check whether the activity is expected, including approved VPNs, travel, automation, or service accounts.
- Escalate to the authorized identity/security team if compromise remains plausible.
- Account disablement, session revocation, and credential reset require an authorized human decision under local policy.

## Possible malware or ransomware
- Correlate endpoint alerts, process execution, file activity, network telemetry, and neighboring hosts.
- Preserve relevant endpoint and network evidence where practical.
- Ask the incident commander or authorized responder to assess containment options.
- Do not run destructive commands or isolate systems automatically from this prototype.

## Severity and confidence
- Severity describes potential impact and urgency; confidence describes how well evidence supports the hypothesis.
- A high severity alert is not proof that an incident is confirmed.
- Record missing information and revisit the assessment when new evidence arrives.

## Human approval
- Disruptive actions such as disabling accounts, blocking addresses, isolating hosts, deleting files, or changing firewall rules must be performed only by authorized staff after review.
- Keep an audit record of the recommendation, reviewer, decision, time, and rationale.
