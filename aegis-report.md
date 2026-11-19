# AEGIS Dependency Analysis & Evidence Report

- **Project:** `/home/z/my-project/audit/Aegis`
- **Generated:** 2026-11-19T01:05:33.719684+00:00
- **Analysis complete:** yes
- **Manifests discovered:** 1
- **Dependency declarations:** 4

## Advisory Summary

- **Raw OSV records:** 2
- **Unique advisory groups:** 1

- **CVE-2025-71176:** 2 OSV record(s)
  - **Identifiers:** CVE-2025-71176, GHSA-6w46-j5rx-g56g, PYSEC-2026-1845

## Findings and Applicability Evidence

### 1. packaging<27.0,>=23.0
- **Source Provenance:** `/home/z/my-project/audit/Aegis/pyproject.toml`
- **Declaration Type:** Direct
- **Vulnerability Query Status:** checked
- No OSV results returned for this package query. This does not guarantee safety.

### 2. tomli>=2.0
- **Source Provenance:** `/home/z/my-project/audit/Aegis/pyproject.toml`
- **Declaration Type:** Direct
- **Vulnerability Query Status:** checked
- No OSV results returned for this package query. This does not guarantee safety.

### 3. pytest<9.0,>=8.0
- **Source Provenance:** `/home/z/my-project/audit/Aegis/pyproject.toml`
- **Declaration Type:** Direct
- **Vulnerability Query Status:** checked
- **Candidate fixed versions (review required):** 9.0.3
- **OSV ID:** GHSA-6w46-j5rx-g56g
  - **Summary:** pytest has vulnerable tmpdir handling
  - **Aliases:** CVE-2025-71176, PYSEC-2026-1845
  - **Known fixed versions:** 9.0.3
- **OSV ID:** PYSEC-2026-1845
  - **Summary:** pytest has vulnerable tmpdir handling
  - **Aliases:** CVE-2025-71176, GHSA-6w46-j5rx-g56g
  - **Known fixed versions:** 9.0.3

### 4. ruff<1.0,>=0.11
- **Source Provenance:** `/home/z/my-project/audit/Aegis/pyproject.toml`
- **Declaration Type:** Direct
- **Vulnerability Query Status:** checked
- No OSV results returned for this package query. This does not guarantee safety.

## Issues and Limitations

No analysis issues were recorded.

## Audit & Verification Evidence

This report provides traceable evidence from static manifest discovery, lockfile-aware resolution, and advisory checks. No dependency files were modified during this scan. All remediation candidates require independent review and isolated verification before deployment.
