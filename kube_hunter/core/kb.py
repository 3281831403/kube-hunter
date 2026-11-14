"""
The kube-hunter knowledge base.

Every vulnerability kube-hunter can report has a page under ``docs/_kb``
(published at https://avd.aquasec.com/kube-hunter/<vid>/). Those pages are
the single source of truth for vulnerability severities: ``KNOWLEDGE_BASE``
mirrors them, and the test suite fails if the two drift apart.

A vulnerability id that is not listed here is unknown to the knowledge base,
and reporting it raises :class:`UnknownVulnerabilityIdError` instead of
silently producing a broken report entry.
"""


class UnknownVulnerabilityIdError(ValueError):
    """Raised when a vulnerability is reported with an id that has no knowledge base page."""


# vid -> severity, mirroring the `severity:` front matter of docs/_kb/<vid>.md
KNOWLEDGE_BASE = {
    "KHV002": "high",
    "KHV003": "high",
    "KHV004": "medium",
    "KHV005": "high",
    "KHV006": "high",
    "KHV007": "high",
    "KHV008": "high",
    "KHV009": "high",
    "KHV010": "high",
    "KHV011": "high",
    "KHV012": "high",
    "KHV013": "high",
    "KHV014": "high",
    "KHV015": "high",
    "KHV016": "high",
    "KHV017": "high",
    "KHV018": "high",
    "KHV019": "high",
    "KHV020": "high",
    "KHV021": "low",
    "KHV022": "critical",
    "KHV023": "medium",
    "KHV024": "medium",
    "KHV025": "medium",
    "KHV026": "high",
    "KHV027": "medium",
    "KHV028": "medium",
    "KHV029": "critical",
    "KHV030": "high",
    "KHV031": "critical",
    "KHV032": "critical",
    "KHV033": "medium",
    "KHV034": "high",
    "KHV035": "medium",
    "KHV036": "high",
    "KHV037": "high",
    "KHV038": "high",
    "KHV039": "high",
    "KHV040": "high",
    "KHV041": "high",
    "KHV042": "high",
    "KHV043": "low",
    "KHV044": "high",
    "KHV045": "high",
    "KHV046": "high",
    "KHV047": "high",
    "KHV048": "high",
    "KHV049": "high",
    "KHV050": "medium",
    "KHV051": "high",
    "KHV052": "medium",
    "KHV053": "high",
    "KHV054": "medium",
}


def get_severity(vid):
    """Returns the knowledge base severity for a vulnerability id.

    Raises UnknownVulnerabilityIdError if the id has no knowledge base page.
    """
    try:
        return KNOWLEDGE_BASE[vid]
    except (KeyError, TypeError):
        raise UnknownVulnerabilityIdError(
            f"Vulnerability id {vid!r} is not in the knowledge base. "
            f"Add a docs/_kb/{vid}.md page and register it in kube_hunter/core/kb.py"
        )
