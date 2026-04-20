"""
Executive summary generator.
Produces 2-3 paragraphs of plain-language analysis for non-technical readers.
"""
from atarus_cloud.models import AuditResult


def generate(result: AuditResult, attack_paths: list = None) -> dict:
    """Generate executive summary sections"""
    attack_paths = attack_paths or []

    crits = [f for f in result.findings if f.severity == "critical"]
    highs = [f for f in result.findings if f.severity == "high"]
    meds = [f for f in result.findings if f.severity == "medium"]
    lows = [f for f in result.findings if f.severity == "low"]

    return {
        "posture": _posture_statement(result, crits, highs, meds, lows),
        "key_risks": _key_risks(result, crits, highs, attack_paths),
        "recommended_actions": _recommended_actions(result, crits, highs, meds),
    }


def _posture_statement(result, crits, highs, meds, lows):
    score = result.overall_score
    total = result.total_findings

    if score >= 90:
        rating = "strong"
        summary = f"The AWS environment demonstrates strong security posture with a score of {score} out of 100."
    elif score >= 75:
        rating = "adequate"
        summary = f"The AWS environment shows adequate security posture with a score of {score} out of 100, with specific areas requiring improvement."
    elif score >= 50:
        rating = "concerning"
        summary = f"The AWS environment has a concerning security posture with a score of {score} out of 100. Multiple high-impact misconfigurations exist that significantly increase the probability of compromise."
    else:
        rating = "critical"
        summary = f"The AWS environment has a critical security posture with a score of {score} out of 100. The combination of misconfigurations present would allow an attacker to compromise the environment with minimal effort."

    breakdown_parts = []
    if crits:
        breakdown_parts.append(f"{len(crits)} critical")
    if highs:
        breakdown_parts.append(f"{len(highs)} high")
    if meds:
        breakdown_parts.append(f"{len(meds)} medium")
    if lows:
        breakdown_parts.append(f"{len(lows)} low")

    if breakdown_parts:
        breakdown = f"The assessment identified {total} finding{'s' if total != 1 else ''}: {', '.join(breakdown_parts)} severity."
        summary = f"{summary} {breakdown}"
    else:
        summary = f"{summary} No findings were identified during the assessment."

    return summary


def _key_risks(result, crits, highs, attack_paths):
    if not crits and not highs and not attack_paths:
        return "No critical or high severity risks were identified. The environment should maintain current controls and continue periodic assessment."

    risks = []

    critical_paths = [p for p in attack_paths if p.severity == "critical"]
    high_paths = [p for p in attack_paths if p.severity == "high"]

    if critical_paths:
        if len(critical_paths) == 1:
            risks.append(f"A critical attack path was identified: {critical_paths[0].title.lower()}. This represents a realistic scenario where an attacker could achieve significant impact by chaining together multiple misconfigurations.")
        else:
            path_titles = [p.title.lower() for p in critical_paths[:3]]
            risks.append(f"Multiple critical attack paths were identified, including {', '.join(path_titles)}. Each represents a realistic scenario where an attacker could chain misconfigurations to achieve significant impact.")

    service_issues = {}
    for f in crits + highs:
        service_issues.setdefault(f.service, []).append(f)

    if service_issues:
        top_services = sorted(service_issues.items(), key=lambda x: len(x[1]), reverse=True)[:3]
        service_summary = []
        for svc, findings in top_services:
            count = len(findings)
            service_summary.append(f"{svc} ({count} issue{'s' if count != 1 else ''})")

        if service_summary:
            risks.append(f"The highest concentration of risk is in {', '.join(service_summary)}. These services should be the focus of immediate remediation efforts.")

    if high_paths and not critical_paths:
        risks.append(f"{len(high_paths)} high severity attack path{'s were' if len(high_paths) != 1 else ' was'} identified, representing significant exposure that should be addressed in the near term.")

    return " ".join(risks) if risks else "Review the findings section for detailed analysis of identified risks."


def _recommended_actions(result, crits, highs, meds):
    if not crits and not highs and not meds:
        return "Continue current security practices. Conduct periodic reassessments to maintain posture."

    quick_wins = []
    strategic = []

    for f in crits + highs:
        effort = f.remediation_effort.lower()
        if "minute" in effort:
            quick_wins.append(f)
        else:
            strategic.append(f)

    actions = []

    if quick_wins:
        count = len(quick_wins)
        if count == 1:
            actions.append(f"One high-impact finding can be resolved in minutes: {quick_wins[0].observation[:100].rstrip('.')}.")
        else:
            actions.append(f"{count} high-impact findings can be resolved within minutes each. These represent the highest return on security investment and should be completed within the first week.")

    if strategic:
        count = len(strategic)
        if count > 0:
            actions.append(f"{count} additional finding{'s require' if count != 1 else ' requires'} more planning and should be scheduled within the next 30 days. These typically involve architectural changes or process adjustments.")

    rem_count = len([f for f in result.findings if f.remediation_cmd and not f.remediation_cmd.startswith("#")])
    if rem_count > 0:
        actions.append(f"This assessment includes an auto-generated remediation script containing {rem_count} actionable AWS CLI command{'s' if rem_count != 1 else ''}. Review the script, validate each command against the environment, and execute it to resolve the majority of findings.")

    actions.append("The full findings section provides detailed observation, risk analysis, and remediation guidance for each item identified.")

    return " ".join(actions)
