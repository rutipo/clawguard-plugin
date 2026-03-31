"""Sensitive content detection for tool inputs and outputs."""

from __future__ import annotations

import math
import re

# Credential patterns
_CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),                       # OpenAI / Stripe secret key
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),                      # GitHub personal access token
    re.compile(r"gho_[a-zA-Z0-9]{36,}"),                      # GitHub OAuth token
    re.compile(r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", re.I),     # Bearer token
    re.compile(r"-----BEGIN\s[\w\s]*PRIVATE KEY-----"),        # PEM private key
    re.compile(r"xox[bpras]-[a-zA-Z0-9\-]+"),                 # Slack token
]

# PII patterns
_PII_PATTERNS = [
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),  # Email
    re.compile(r"\b\d{3}[\-.\s]?\d{3}[\-.\s]?\d{4}\b"),                 # US phone
]

_PATTERN_LABELS = {
    0: "aws_key",
    1: "secret_key",
    2: "github_pat",
    3: "github_oauth",
    4: "bearer_token",
    5: "private_key",
    6: "slack_token",
    7: "email_address",
    8: "phone_number",
}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _find_high_entropy_strings(text: str, min_length: int = 20, threshold: float = 4.5) -> list[str]:
    """Find substrings that look like API keys based on high entropy."""
    results = []
    # Split on whitespace and common delimiters
    tokens = re.split(r'[\s"\'=:,;\[\]{}()|]+', text)
    for token in tokens:
        if len(token) >= min_length and _shannon_entropy(token) >= threshold:
            results.append(token[:40])
    return results


def detect_sensitive_content(text: str) -> list[str]:
    """Detect sensitive content in text. Returns list of pattern labels found."""
    if not text:
        return []

    findings: list[str] = []

    # Check credential and PII patterns
    all_patterns = _CREDENTIAL_PATTERNS + _PII_PATTERNS
    for idx, pattern in enumerate(all_patterns):
        if pattern.search(text):
            label = _PATTERN_LABELS.get(idx, f"pattern_{idx}")
            findings.append(label)

    # Check for high-entropy strings (likely API keys)
    high_entropy = _find_high_entropy_strings(text)
    if high_entropy:
        findings.append("high_entropy_string")

    return findings
