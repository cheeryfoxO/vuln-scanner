"""Cloud storage bucket enumeration -- AWS S3, GCP, Azure Blob."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule

# ── Bucket name generation ────────────────────────────────────────────

_BASE_PATTERNS = [
    "backup", "prod", "dev", "staging", "test", "qa",
    "assets", "static", "media", "files", "data", "logs",
]


def _generate_bucket_names(domain):
    """Generate candidate bucket names from a target domain.

    Args:
        domain: e.g. "example.com" or "sub.example.com"

    Returns:
        List of candidate bucket name strings (max ~50).
    """
    domain = domain.lower().strip()
    if not domain or "." not in domain:
        return []

    parts = domain.split(".")
    base = parts[0]  # e.g. "example"
    domain_dash = domain.replace(".", "-")  # e.g. "example-com"

    candidates = set()

    # Domain-derived names
    candidates.add(base)
    candidates.add(domain_dash)
    candidates.add(domain)  # original domain with dots

    # Suffixed patterns
    for pattern in _BASE_PATTERNS:
        candidates.add(f"{base}-{pattern}")
        candidates.add(f"{domain_dash}-{pattern}")

    # For multi-part domains (e.g. sub.example.com), also try sub-domain parts
    if len(parts) >= 3:
        sub_name = parts[-3]
        candidates.add(sub_name)
        sub_dash = "-".join(parts[:-1])
        candidates.add(sub_dash)

    # Sort for deterministic output, cap at 50
    result = sorted(candidates)
    return result[:50]


# ── Response classification ───────────────────────────────────────────

# AWS S3 XML error codes
AWS_ACCESS_DENIED = "AccessDenied"
AWS_NO_SUCH_BUCKET = "NoSuchBucket"
AWS_LIST_BUCKET_RESULT = "ListBucketResult"

# Azure Blob XML error codes
AZURE_NO_SUCH_BUCKET = "<Code>ContainerNotFound</Code>"
AZURE_ACCESS_DENIED = "<Code>AuthorizationFailure</Code>"

# GCP JSON error patterns
GCP_NO_SUCH_BUCKET = "<Code>NoSuchBucket</Code>"
GCP_ACCESS_DENIED = "<Code>AccessDenied</Code>"


def _classify_response(status_code, text, provider):
    """Classify a bucket HTTP response into severity and description.

    Args:
        status_code: HTTP status code.
        text: Response body text.
        provider: One of "AWS", "GCP", "Azure".

    Returns:
        (severity: str, desc: str) -- severity is one of
        "critical", "high", "medium", "info".
    """
    text_lower = (text or "").lower()

    # ── Public listing (critical) ──
    if AWS_LIST_BUCKET_RESULT.lower() in text_lower:
        return "critical", "Publicly listable bucket — ListBucketResult returned"

    # ── Access denied (high) ──
    if status_code == 403:
        return "high", "Bucket exists but access denied (HTTP 403)"
    if AWS_ACCESS_DENIED.lower() in text_lower:
        return "high", "Bucket exists but access denied (AccessDenied)"

    # ── GCP / Azure access denied patterns ──
    if provider == "GCP" and GCP_ACCESS_DENIED.lower() in text_lower:
        return "high", "Bucket exists but access denied (AccessDenied)"
    if provider == "Azure" and AZURE_ACCESS_DENIED.lower() in text_lower:
        return "high", "Bucket exists but access denied (AuthorizationFailure)"

    # ── Does not exist (info) ──
    if status_code == 404:
        return "info", "Bucket does not exist (HTTP 404)"
    if AWS_NO_SUCH_BUCKET.lower() in text_lower:
        return "info", "Bucket does not exist (NoSuchBucket)"
    if provider == "GCP" and GCP_NO_SUCH_BUCKET.lower() in text_lower:
        return "info", "Bucket does not exist (NoSuchBucket)"
    if provider == "Azure" and AZURE_NO_SUCH_BUCKET.lower() in text_lower:
        return "info", "Bucket does not exist (ContainerNotFound)"

    # ── Exists but unclear status (medium) ──
    if 200 <= status_code < 500:
        return "medium", f"Bucket returned HTTP {status_code} (exists, unknown status)"

    # ── Other (info) ──
    return "info", f"Bucket returned HTTP {status_code}"


# ── Bucket URL templates ──────────────────────────────────────────────

_PROVIDERS = {
    "AWS": "https://{bucket}.s3.amazonaws.com",
    "GCP": "https://{bucket}.storage.googleapis.com",
    "Azure": "https://{bucket}.blob.core.windows.net",
}


def _check_bucket(bucket, provider, request_handler):
    """Check if a bucket exists at the given cloud provider.

    Returns a finding dict or None if the request failed completely.
    """
    url = _PROVIDERS[provider].format(bucket=bucket)
    try:
        resp = request_handler.get(url, timeout=10, allow_redirects=False)
        severity, desc = _classify_response(resp.status_code, resp.text, provider)
        return {
            "type": "s3_bucket",
            "severity": severity,
            "provider": provider,
            "bucket": bucket,
            "url": url,
            "desc": desc,
            "evidence": f"HTTP {resp.status_code}",
        }
    except Exception:
        return None


# ── Module ─────────────────────────────────────────────────────────────

class S3Module(BaseModule):
    """Enumerate cloud storage buckets based on target domain."""

    name = "s3"
    description = "Enumerate cloud storage buckets (AWS S3, GCP, Azure) from domain"
    requires_url = False

    def run(self, target, request_handler, output):
        """Generate bucket names and check against cloud providers.

        Args:
            target: Domain name (e.g. "example.com").
            request_handler: RequestHandler instance.
            output: Output instance.

        Returns:
            {"module": "s3", "findings": [...]}
        """
        if not target or "." not in target:
            output.log_progress("s3: target must be a domain name (e.g. example.com)")
            return {"module": self.name, "findings": []}

        bucket_names = _generate_bucket_names(target)
        output.log_progress(
            f"s3: generated {len(bucket_names)} bucket name candidates from {target}"
        )

        # Build task list: each (bucket, provider) pair
        tasks = []
        for bucket in bucket_names:
            for provider in _PROVIDERS:
                tasks.append((bucket, provider))

        output.log_progress(
            f"s3: checking {len(tasks)} bucket/provider combinations "
            f"({len(bucket_names)} names x {len(_PROVIDERS)} providers)"
        )

        findings = []
        bar = output.create_progress_bar("s3", len(tasks))

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {}
            for bucket, provider in tasks:
                fut = pool.submit(_check_bucket, bucket, provider, request_handler)
                futures[fut] = (bucket, provider)

            for future in as_completed(futures):
                bucket, provider = futures[future]
                try:
                    result = future.result()
                    if result is not None:
                        findings.append(result)
                        if result["severity"] in ("critical", "high"):
                            output.log_finding(self.name, result)
                        elif result["severity"] == "medium":
                            output.log_finding(self.name, result)
                except Exception:
                    pass
                output.update_progress(bar)

        bar.close()

        # Sort by severity priority
        severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

        # Log info-level findings only in verbose mode
        for f in findings:
            if f["severity"] not in ("critical", "high", "medium"):
                output.log_progress(
                    f"s3: {f['provider']} {f['bucket']} — {f['desc']}"
                )

        output.log_progress(
            f"s3: {len(findings)} bucket findings "
            f"({len([f for f in findings if f['severity'] == 'critical'])} critical, "
            f"{len([f for f in findings if f['severity'] == 'high'])} high)"
        )

        return {"module": self.name, "findings": findings}
