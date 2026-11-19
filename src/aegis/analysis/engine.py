"""Read-only project analysis orchestration."""

from datetime import datetime, timezone
from pathlib import Path

from packaging.version import InvalidVersion, Version

from aegis.discovery.manifests import discover_manifests
from aegis.models import AnalysisIssue, AnalysisReport, DependencyFinding
from aegis.parsing.lockfile import lockfile_to_dependencies, parse_lockfile
from aegis.parsing.pyproject import parse_pyproject
from aegis.parsing.requirements import parse_requirements_file, to_dependencies
from aegis.remediation.candidates import suggest_fixed_versions
from aegis.vulnerability.advisories import group_advisories
from aegis.vulnerability.applicability import is_vulnerability_applicable
from aegis.vulnerability.osv import OSVError, query_vulnerabilities


def _pinned_versions(specifier: str) -> list[str]:
    """Extract exact version pins from a dependency specifier.

    Mirrors the OSV client's pin detection so applicability checks use the
    same notion of "pinned version" as the OSV query payload.
    """
    pins: list[str] = []
    for part in specifier.split(","):
        part = part.strip()
        if part.startswith("==") and not part.endswith(".*"):
            pins.append(part[2:])
    return pins


def _filter_applicability(finding: DependencyFinding) -> bool:
    """Filter finding vulnerabilities by applicability to the pinned version.

    When the dependency has exactly one pinned version, vulnerabilities that
    are explicitly not applicable (return False) are dropped. Undecidable
    cases (None) are retained as conservative evidence. Recommended fixed
    versions are restricted to vulnerabilities confirmed as applicable (True).

    Returns True when applicability filtering was applied (and
    ``recommended_versions`` was populated); False when no filtering was
    possible and the caller should fall back to ``suggest_fixed_versions``.
    """
    if not finding.vulnerabilities:
        return False

    pins = _pinned_versions(finding.dependency.specifier)
    if len(pins) != 1:
        # Without a single exact pin, applicability cannot be decided;
        # fall back to the existing aggregate behaviour.
        return False

    version_str = pins[0]
    kept: list = []
    applicable_fixed: set[str] = set()

    for vuln in finding.vulnerabilities:
        applicable = is_vulnerability_applicable(vuln, version_str)
        if applicable is False:
            # Explicitly not applicable to this pinned version; drop it.
            continue
        kept.append(vuln)
        if applicable is True:
            applicable_fixed.update(vuln.fixed_versions)

    finding.vulnerabilities = kept

    candidates: set[Version] = set()
    for version in applicable_fixed:
        try:
            candidates.add(Version(version))
        except InvalidVersion:
            continue
    finding.recommended_versions = [str(v) for v in sorted(candidates)]
    return True


def analyze_project(
    project: str | Path, check_vulnerabilities: bool = True, timeout: float = 12.0
) -> AnalysisReport:
    root = Path(project).expanduser().resolve()
    manifests = discover_manifests(root)
    report = AnalysisReport(
        project=str(root),
        generated_at=datetime.now(timezone.utc).isoformat(),
        manifests=[str(p) for p in manifests],
    )
    if not manifests:
        report.issues.append(
            AnalysisIssue(
                "NO_MANIFESTS",
                "No supported root-level dependency manifests were found.",
            )
        )
    for manifest in manifests:
        if manifest.name == "requirements.txt":
            parsed = parse_requirements_file(manifest)
            deps, issues = to_dependencies(parsed)
            report.dependencies.extend(deps)
            report.issues.extend(issues)
        elif manifest.name == "requirements.lock":
            parsed = parse_lockfile(manifest)
            deps, issues = lockfile_to_dependencies(parsed)
            report.dependencies.extend(deps)
            report.issues.extend(issues)
        elif manifest.name == "pyproject.toml":
            deps, issues = parse_pyproject(manifest)
            report.dependencies.extend(deps)
            report.issues.extend(issues)

    cache = {}
    for dep in report.dependencies:
        key = (dep.name.lower().replace("_", "-"), dep.specifier)
        finding = DependencyFinding(dependency=dep)
        if check_vulnerabilities:
            if key not in cache:
                try:
                    cache[key] = (query_vulnerabilities(dep, timeout), None)
                except OSVError as exc:
                    cache[key] = ([], str(exc))
            vulns, error = cache[key]
            finding.vulnerabilities = vulns
            finding.status = "checked" if error is None else "error"
            if error:
                report.issues.append(
                    AnalysisIssue(
                        "OSV_QUERY_FAILED",
                        f"Could not query OSV for {dep.name}: {error}",
                        dep.source,
                        dep.line_number,
                    )
                )
            # Apply per-finding applicability filtering before deriving
            # recommended versions so non-applicable advisories do not
            # pollute remediation candidates. Offline findings (empty
            # vulnerabilities) are unaffected. When filtering does not
            # apply (no pinned version, no vulnerabilities), fall back to
            # the existing aggregate behaviour.
            applicability_applied = _filter_applicability(finding)
            if not applicability_applied:
                finding.recommended_versions = suggest_fixed_versions(finding)
        else:
            finding.recommended_versions = suggest_fixed_versions(finding)
        report.findings.append(finding)
    report.complete = not any(i.severity == "error" for i in report.issues) and not any(
        i.code
        in {
            "REQUIREMENTS_PARSE",
            "PYPROJECT_REQUIREMENT",
            "PYPROJECT_SCOPE",
            "OSV_QUERY_FAILED",
        }
        for i in report.issues
    )
    # Collect all vulnerabilities across findings and pre-compute advisory
    # groups once. Case-insensitive deduplication happens here so JSON
    # output and Markdown writers share the same grouped view rather than
    # each re-deriving it (and potentially diverging).
    all_vulnerabilities = [
        vuln
        for finding in report.findings
        for vuln in finding.vulnerabilities
    ]
    report.grouped_advisories = group_advisories(all_vulnerabilities)
    return report