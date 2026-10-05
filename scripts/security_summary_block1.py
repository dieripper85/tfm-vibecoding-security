from pathlib import Path
from collections import defaultdict
import csv

ROOT = Path(__file__).resolve().parents[1]

INPUT = ROOT / "results" / "block1" / "block1_raw_findings.csv"
OUTPUT = ROOT / "results" / "block1" / "block1_security_summary.csv"
CLASSIFIED = ROOT / "results" / "block1" / "block1_findings_classified.csv"

rows = list(
    csv.DictReader(
        INPUT.open(
            encoding="utf-8-sig"
        )
    )
)

classified = []

security_samples = defaultdict(set)
security_raw = defaultdict(int)
security_cwes = defaultdict(set)

for row in rows:

    rule = row["rule_id"]
    cwe = row["cwe"].strip()

    if ".maintainability." in rule:
        scope = "QUALITY"

    elif cwe or ".security." in rule:
        scope = "SECURITY"

    else:
        scope = "OTHER"

    row["scope"] = scope
    classified.append(row)

    if scope != "SECURITY":
        continue

    condition = row["condition"]
    sample = row["sample_id"]

    security_samples[condition].add(
        sample
    )

    security_raw[condition] += 1

    if cwe:
        for item in cwe.split("|"):
            item = item.strip()

            if item:
                security_cwes[
                    (condition, sample)
                ].add(item)


# Guardar clasificación completa
fields = list(rows[0].keys())

if "scope" not in fields:
    fields.append("scope")

with CLASSIFIED.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(classified)


conditions = [
    "UNDERSPEC",
    "NEUTRAL",
    "SECURE"
]

summary = []

for condition in conditions:

    affected = len(
        security_samples[condition]
    )

    unique_cwe_total = sum(
        len(cwes)
        for (cond, sample), cwes
        in security_cwes.items()
        if cond == condition
    )

    summary.append({
        "condition": condition,
        "samples": 30,
        "samples_with_security_findings":
            affected,
        "rate_security_findings_pct":
            round(
                affected / 30 * 100,
                2
            ),
        "security_raw_findings":
            security_raw[condition],
        "unique_cwe_per_sample_total":
            unique_cwe_total,
        "avg_security_findings_per_sample":
            round(
                security_raw[condition]
                / 30,
                2
            ),
    })


with OUTPUT.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    fields = [
        "condition",
        "samples",
        "samples_with_security_findings",
        "rate_security_findings_pct",
        "security_raw_findings",
        "unique_cwe_per_sample_total",
        "avg_security_findings_per_sample",
    ]

    writer = csv.DictWriter(
        f,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(summary)


print("Generados:")
print(CLASSIFIED)
print(OUTPUT)