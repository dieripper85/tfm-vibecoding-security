from pathlib import Path
import json
import csv
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]

GENERATED_DIR = ROOT / "data" / "pilot" / "block1" / "generated"
SEMGREP_DIR = ROOT / "data" / "pilot" / "block1" / "semgrep"
RESULTS_DIR = ROOT / "results" / "pilot"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

findings_rows = []

summary = defaultdict(
    lambda: {
        "samples": 0,
        "samples_with_findings": 0,
        "findings": 0
    }
)

metadata_files = sorted(
    GENERATED_DIR.glob("PILOT_B1_*.json")
)

for metadata_file in metadata_files:

    metadata = json.loads(
        metadata_file.read_text(encoding="utf-8")
    )

    sample_id = metadata["sample_id"]

    semgrep_file = SEMGREP_DIR / f"{sample_id}.json"

    findings = []

    if semgrep_file.exists():

        result = json.loads(
            semgrep_file.read_text(encoding="utf-8")
        )

        findings = result.get("results", [])

    key = (
        metadata["scenario_id"],
        metadata["condition"]
    )

    summary[key]["samples"] += 1
    summary[key]["findings"] += len(findings)

    if findings:
        summary[key]["samples_with_findings"] += 1

    if not findings:

        findings_rows.append({
            "sample_id": sample_id,
            "scenario_id": metadata["scenario_id"],
            "scenario_name": metadata["scenario_name"],
            "condition": metadata["condition"],
            "repetition": metadata["repetition"],
            "finding": 0,
            "rule_id": "",
            "severity": "",
            "cwe": "",
            "owasp": "",
            "message": ""
        })

        continue

    for finding in findings:

        extra = finding.get("extra", {})
        metadata_rule = extra.get("metadata", {}) or {}

        cwe = metadata_rule.get("cwe", "")
        owasp = metadata_rule.get("owasp", "")

        if isinstance(cwe, list):
            cwe = " | ".join(map(str, cwe))

        if isinstance(owasp, list):
            owasp = " | ".join(map(str, owasp))

        findings_rows.append({
            "sample_id": sample_id,
            "scenario_id": metadata["scenario_id"],
            "scenario_name": metadata["scenario_name"],
            "condition": metadata["condition"],
            "repetition": metadata["repetition"],
            "finding": 1,
            "rule_id": finding.get("check_id", ""),
            "severity": extra.get("severity", ""),
            "cwe": cwe,
            "owasp": owasp,
            "message": extra.get("message", "")
        })


# CSV DETALLADO
detail_file = RESULTS_DIR / "pilot_findings.csv"

fields = [
    "sample_id",
    "scenario_id",
    "scenario_name",
    "condition",
    "repetition",
    "finding",
    "rule_id",
    "severity",
    "cwe",
    "owasp",
    "message"
]

with detail_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(findings_rows)


# CSV RESUMEN
summary_file = RESULTS_DIR / "pilot_summary.csv"

summary_fields = [
    "scenario_id",
    "condition",
    "samples",
    "samples_with_findings",
    "rate_samples_with_findings_pct",
    "total_findings",
    "avg_findings_per_sample"
]

with summary_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=summary_fields
    )

    writer.writeheader()

    for (scenario, condition), values in sorted(summary.items()):

        samples = values["samples"]
        affected = values["samples_with_findings"]
        findings = values["findings"]

        writer.writerow({
            "scenario_id": scenario,
            "condition": condition,
            "samples": samples,
            "samples_with_findings": affected,
            "rate_samples_with_findings_pct":
                round((affected / samples) * 100, 2)
                if samples else 0,
            "total_findings": findings,
            "avg_findings_per_sample":
                round(findings / samples, 2)
                if samples else 0
        })


print("Archivos generados:")
print(detail_file)
print(summary_file)