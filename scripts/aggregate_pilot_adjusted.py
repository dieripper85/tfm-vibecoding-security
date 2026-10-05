from pathlib import Path
import json
import csv
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]

GENERATED_DIR = (
    ROOT
    / "data"
    / "pilot_adjusted"
    / "block1"
    / "generated"
)

SEMGREP_DIR = (
    ROOT
    / "data"
    / "pilot_adjusted"
    / "block1"
    / "semgrep"
)

RESULTS_DIR = (
    ROOT
    / "results"
    / "pilot_adjusted"
)

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

rows = []

summary = defaultdict(
    lambda: {
        "samples": 0,
        "samples_with_findings": 0,
        "raw_findings": 0,
        "unique_cwe": 0
    }
)

metadata_files = sorted(
    GENERATED_DIR.glob("PILOT2_B1_*.json")
)

for metadata_file in metadata_files:

    metadata = json.loads(
        metadata_file.read_text(
            encoding="utf-8"
        )
    )

    sample_id = metadata["sample_id"]

    semgrep_file = (
        SEMGREP_DIR
        / f"{sample_id}.json"
    )

    result = json.loads(
        semgrep_file.read_text(
            encoding="utf-8"
        )
    )

    findings = result.get(
        "results",
        []
    )

    unique_cwes = set()

    key = (
        metadata["scenario_id"],
        metadata["condition"]
    )

    summary[key]["samples"] += 1
    summary[key]["raw_findings"] += len(findings)

    if findings:
        summary[key]["samples_with_findings"] += 1

    for finding in findings:

        extra = finding.get(
            "extra",
            {}
        )

        rule_metadata = extra.get(
            "metadata",
            {}
        ) or {}

        cwe = rule_metadata.get(
            "cwe",
            ""
        )

        owasp = rule_metadata.get(
            "owasp",
            ""
        )

        if isinstance(cwe, list):
            cwe_text = " | ".join(
                map(str, cwe)
            )
        else:
            cwe_text = str(cwe)

        if isinstance(owasp, list):
            owasp_text = " | ".join(
                map(str, owasp)
            )
        else:
            owasp_text = str(owasp)

        if cwe_text:
            unique_cwes.add(cwe_text)

        rows.append({
            "sample_id": sample_id,
            "scenario_id":
                metadata["scenario_id"],
            "condition":
                metadata["condition"],
            "repetition":
                metadata["repetition"],
            "rule_id":
                finding.get(
                    "check_id",
                    ""
                ),
            "severity":
                extra.get(
                    "severity",
                    ""
                ),
            "cwe":
                cwe_text,
            "owasp":
                owasp_text,
            "message":
                extra.get(
                    "message",
                    ""
                )
        })

    summary[key]["unique_cwe"] += len(
        unique_cwes
    )


detail_file = (
    RESULTS_DIR
    / "pilot_adjusted_findings.csv"
)

fields = [
    "sample_id",
    "scenario_id",
    "condition",
    "repetition",
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
    writer.writerows(rows)


summary_file = (
    RESULTS_DIR
    / "pilot_adjusted_summary.csv"
)

summary_fields = [
    "scenario_id",
    "condition",
    "samples",
    "samples_with_findings",
    "rate_samples_with_findings_pct",
    "raw_findings",
    "unique_cwe_per_samples_total"
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

    for (
        scenario,
        condition
    ), values in sorted(
        summary.items()
    ):

        samples = values["samples"]
        affected = values[
            "samples_with_findings"
        ]

        writer.writerow({
            "scenario_id":
                scenario,
            "condition":
                condition,
            "samples":
                samples,
            "samples_with_findings":
                affected,
            "rate_samples_with_findings_pct":
                round(
                    (affected / samples) * 100,
                    2
                ) if samples else 0,
            "raw_findings":
                values["raw_findings"],
            "unique_cwe_per_samples_total":
                values["unique_cwe"]
        })


print("Generados:")
print(detail_file)
print(summary_file)