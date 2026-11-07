# AI-Assisted Vulnerability Detection and Remediation

## Problem Statement

Software teams rely on a mix of manual code review and security tools to find vulnerabilities. These approaches can produce fragmented or noisy findings, require substantial specialist time to interpret, and leave developers to research and implement fixes across multiple tools. As a result, security issues may take too long to validate and remediate, especially when teams have limited security expertise or large codebases.

This project will develop a developer-facing tool that analyzes source code in a repository the user controls, identifies likely security issues, explains their evidence and potential impact, and recommends focused remediation. The system will prioritize findings by risk and confidence, connect recommendations to the relevant code, and measure time from detection to a reviewed fix. Any proposed change will be shown for human review before it is applied; the system will not claim that a repository is vulnerability-free.

## Aim

Reduce the time and effort required to identify, understand, prioritize, and safely remediate common vulnerabilities in locally supplied source code, while keeping developers in control of code changes.

## Objectives

1. Analyze a selected local repository using established static-analysis and dependency-audit capabilities where available.
2. Normalize and deduplicate findings, linking each result to its source location, evidence, severity, and confidence.
3. Rank findings using transparent criteria so developers can address the most consequential issues first.
4. Generate concise explanations and targeted remediation proposals grounded in the finding and surrounding code.
5. Present proposed changes as reviewable diffs; require explicit developer approval before modifying files.
6. Record scan and remediation timings, review outcomes, and validation results to evaluate whether the workflow saves time without reducing fix quality.

## Initial Scope

- Input: a user-selected local repository and its supported source files and dependency manifests.
- Analysis: static checks and dependency advisories from established tools, with optional AI assistance for explanation and patch suggestions.
- Output: an ordered report containing finding, file and line, evidence, severity, confidence, and suggested next action.
- Remediation: a proposed patch that can be reviewed, accepted, edited, or rejected by the developer.
- Validation: rerun relevant checks and tests after an approved patch, and report unresolved or newly introduced findings.

## Out of Scope

- Scanning public or third-party systems, networks, or repositories without authorization.
- Exploiting vulnerabilities, establishing access, or performing penetration testing.
- Applying code changes silently or making unsupported guarantees about security.
- Replacing security experts, code review, testing, or a full software-development lifecycle security program.

## Success Measures

Evaluate the MVP against a fixed, documented set of intentionally vulnerable and non-vulnerable sample projects. Establish a baseline before testing and report results by language and finding category.

- **Detection quality:** precision and recall for the supported vulnerability categories.
- **Triage effort:** time a developer takes to understand and prioritize a valid finding.
- **Remediation time:** median time from a confirmed finding to an approved, validated fix.
- **Fix quality:** proportion of accepted fixes that pass relevant tests and remove the targeted finding without introducing a new issue.
- **Noise:** duplicate and false-positive findings per project.
- **Control and traceability:** every applied patch has explicit approval and an inspectable diff; every result records which checks produced it.

Targets should be set after a baseline measurement; avoid claiming a percentage improvement until it has been measured on representative projects.

## MVP Workflow

1. The developer selects a local repository and starts a scan.
2. The tool runs configured static and dependency checks and collects their structured results.
3. The tool groups duplicates and presents findings with evidence, location, severity, and confidence.
4. The developer selects a finding to see an explanation and a suggested remediation.
5. The tool displays any proposed edit as a diff and waits for explicit approval.
6. After approval, the tool runs relevant checks and tests, then reports whether the finding was resolved and what remains uncertain.

## Key Design Requirements

- **Human approval:** generated changes are proposals, never silent edits.
- **Evidence first:** recommendations must refer to a concrete finding and code location; uncertainty must be visible.
- **Least privilege:** scan only the repository selected by the user and avoid sending source code to external services unless the user explicitly enables that behavior.
- **Reproducibility:** retain the tools, rule versions, configuration, and validation results used for each scan.
- **Safe failure:** if a check or validation step cannot run, report that limitation instead of treating it as a pass.

## Working Research Question

Can an evidence-grounded, human-approved AI remediation workflow reduce developer time from confirmed vulnerability detection to validated fix, compared with a conventional scan-and-manual-remediation workflow, without lowering fix quality or obscuring uncertainty?