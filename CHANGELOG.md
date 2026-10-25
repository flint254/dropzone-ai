# Changelog

## v0.4.0 — Two-agent evidence review and expanded evaluation

- Expanded the synthetic alert benchmark from 8 to 32 cases, including benign lookalikes, ambiguous evidence, identity, endpoint, cloud, email, network, and data-loss alerts.
- Added a second evidence-review agent that independently classifies each generated summary/finding as supported, contradicted, or insufficient against the cited passages.
- The system now fails closed to deterministic triage if the reviewer is unavailable or the summary is not supported; unsupported individual findings are excluded.
- Persists reviewer assessments and displays them in the incident detail panel.
- Added 30 labelled claim/passage pairs and `POST /evaluation/reviewer-calibration` to measure the reviewer against gold labels.
- The alert evaluation now compares rule-baseline priority accuracy against final two-agent accuracy and reports claim support rates and reviewer-blocked summaries.
- Added regression tests for reviewer fail-closed behavior and dataset coverage.

## v0.3.0 — Reliability-first single investigation

- Reworked the small document retriever to use a BM25-like lexical score and stable section-level line citations.
- Added a bounded investigation trace for deterministic triage, retrieval, model response, and quality gate.
- Rejects model output without an allowlisted citation or valid response shape; uses deterministic fallback on provider or validation failures.
- Records workflow trace and quality status in SQLite with a safe migration for existing databases.
- Added dashboard display for workflow trace and quality status.
- Corrected the event user mapping on re-investigation.
- Strengthened evaluation citation checks and tracks rejected model citation IDs.
- Added mocked model tests for invalid citations, valid citations, missing summaries, and mandatory approval for disruptive recommendations.

## Known limitations

- Retrieval is lexical, not semantic.
- Citation allowlisting proves source provenance, not semantic entailment.
- The v0.3 alert labels were a starter set; v0.4 expands the set to 32 synthetic cases, still not production ground truth.
- API-key RBAC is suitable only for local portfolio demonstration; production should use an identity provider and hardened deployment.
- v0.4 adds a bounded two-agent sequence, not a general-purpose multi-agent orchestration framework.
