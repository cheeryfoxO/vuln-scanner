"""Result deduplication -- removes duplicate findings across all modules."""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _extract_url(finding):
    """Extract best URL from a finding dict.

    Tries: url, host, source, endpoint, then scans evidence string for URLs.
    Returns "" if nothing found.
    """
    # Direct URL fields
    for key in ("url", "host", "source", "endpoint"):
        val = finding.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()

    # Scan evidence string for a URL pattern
    evidence = finding.get("evidence", "")
    if isinstance(evidence, str):
        import re
        m = re.search(r"https?://[^\s\"']+", evidence)
        if m:
            return m.group(0)

    return ""


def _dedup_key(finding, strategy):
    """Generate a dedup key for a finding based on strategy.

    - url_type: (url, type)
    - type_evidence: (type, evidence) as a hashable representation
    - strict: frozenset of all (k, str(v)) pairs
    """
    if strategy == "url_type":
        url = _extract_url(finding)
        ftype = finding.get("type", "")
        return (url, ftype)

    if strategy == "type_evidence":
        ftype = finding.get("type", "")
        evidence = finding.get("evidence", "")
        if not isinstance(evidence, str):
            evidence = str(evidence)
        return (ftype, evidence)

    if strategy == "strict":
        return frozenset((k, str(v)) for k, v in sorted(finding.items()))

    raise ValueError(f"Unknown dedup strategy: {strategy}")


def _select_better(finding_a, finding_b):
    """Select the better finding between two duplicates.

    Keeps the one with higher severity (critical > high > medium > low > info).
    If same severity, keeps the one with more detail (longer evidence or desc).
    """
    sev_a = SEVERITY_ORDER.get(finding_a.get("severity", "info"), 4)
    sev_b = SEVERITY_ORDER.get(finding_b.get("severity", "info"), 4)

    if sev_a < sev_b:
        return finding_a
    if sev_b < sev_a:
        return finding_b

    # Same severity — pick the one with more detail
    detail_a = len(str(finding_a.get("evidence", ""))) + len(str(finding_a.get("desc", "")))
    detail_b = len(str(finding_b.get("evidence", ""))) + len(str(finding_b.get("desc", "")))
    if detail_a >= detail_b:
        return finding_a
    return finding_b


def deduplicate_findings(findings_dict, strategy="url_type"):
    """Deduplicate findings across all modules.

    Args:
        findings_dict: {module_name: [finding_dict, ...]}
        strategy: dedup strategy
            - "url_type": same url + type -> keep highest severity
            - "type_evidence": same type + evidence -> keep first
            - "strict": all fields must match exactly

    Returns:
        ({module_name: [deduped_findings]}, {module_name: (before, after, removed)})
    """
    deduped = {}
    stats = {}

    for module_name, findings in findings_dict.items():
        before = len(findings)
        seen = {}  # dedup_key -> finding

        for finding in findings:
            key = _dedup_key(finding, strategy)
            if key in seen:
                seen[key] = _select_better(seen[key], finding)
            else:
                seen[key] = finding

        deduped_list = list(seen.values())
        after = len(deduped_list)
        removed = before - after
        deduped[module_name] = deduped_list
        stats[module_name] = (before, after, removed)

    return deduped, stats
