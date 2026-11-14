# flake8: noqa: E402
import json
import re
from pathlib import Path

import pytest

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.core.kb import KNOWLEDGE_BASE, UnknownVulnerabilityIdError
from kube_hunter.core.events.types import Vulnerability
from kube_hunter.core.types import KubernetesCluster
from kube_hunter.modules.hunting.apiserver import ServerApiAccess
from kube_hunter.modules.hunting.dashboard import DashboardExposed, KubeDashboard

REPO_ROOT = Path(__file__).resolve().parents[2]
KB_PAGES_DIR = REPO_ROOT / "docs" / "_kb"


def parse_kb_page(path):
    """Returns (vid, severity) parsed from a knowledge base page's front matter."""
    text = path.read_text()
    front_matter = text.split("---")[1]
    vid = re.search(r"^vid:\s*(\S+)", front_matter, re.MULTILINE).group(1)
    severity = re.search(r"^severity:\s*(\S+)", front_matter, re.MULTILINE).group(1)
    return vid, severity


def test_knowledge_base_mirrors_kb_pages():
    """The in-code knowledge base must match the docs/_kb pages exactly."""
    pages = dict(parse_kb_page(page) for page in KB_PAGES_DIR.glob("KHV*.md"))
    assert pages, "no knowledge base pages found"
    assert KNOWLEDGE_BASE == pages


def test_all_reported_vids_are_in_the_knowledge_base():
    """Every vid literal used by hunters must exist in the knowledge base."""
    used_vids = set()
    for source in (REPO_ROOT / "kube_hunter").rglob("*.py"):
        used_vids.update(re.findall(r'vid="(KHV\d+)"', source.read_text()))
    assert used_vids, "no vids found in source"
    unknown = used_vids - KNOWLEDGE_BASE.keys()
    assert not unknown, f"vids missing from the knowledge base: {unknown}"


def test_vulnerability_without_vid_raises():
    with pytest.raises(UnknownVulnerabilityIdError):
        Vulnerability(KubernetesCluster, "No ID")


def test_vulnerability_with_unknown_vid_raises():
    with pytest.raises(UnknownVulnerabilityIdError):
        Vulnerability(KubernetesCluster, "Unknown ID", vid="KHV999")


def test_same_vid_same_severity_on_every_path():
    """KHV005 must report the knowledge base severity, with or without a token."""
    anonymous = ServerApiAccess(evidence="", using_token=False)
    with_token = ServerApiAccess(evidence="", using_token=True)
    assert anonymous.get_vid() == with_token.get_vid() == "KHV005"
    assert anonymous.get_severity() == with_token.get_severity() == KNOWLEDGE_BASE["KHV005"]


def test_critical_severity_is_expressible():
    assert KNOWLEDGE_BASE["KHV029"] == "critical"
    assert DashboardExposed(nodes=[]).get_severity() == "critical"


def test_reporters_agree_on_severity():
    """json, yaml and plain reports must all show the knowledge base severity."""
    from kube_hunter.modules.report import collector
    from kube_hunter.modules.report.factory import JSONReporter, PlainReporter, YAMLReporter

    vuln = DashboardExposed(nodes=[])
    vuln.hunter = KubeDashboard

    with collector.vulnerabilities_lock:
        collector.vulnerabilities.append(vuln)
    try:
        json_report = json.loads(JSONReporter().get_report(statistics=False))
        (json_vuln,) = [v for v in json_report["vulnerabilities"] if v["vid"] == "KHV029"]
        assert json_vuln["severity"] == "critical"
        assert "/none/" not in json_vuln["avd_reference"]

        yaml_report = YAMLReporter().get_report(statistics=False)
        assert "severity: critical" in yaml_report

        plain_report = PlainReporter().get_report(statistics=False)
        assert "SEVERITY" in plain_report.upper()
        assert "critical" in plain_report
    finally:
        with collector.vulnerabilities_lock:
            collector.vulnerabilities.remove(vuln)
