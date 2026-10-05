from pathlib import Path
from collections import defaultdict
import csv
import json
import re

ROOT = Path(__file__).resolve().parents[1]

GENERATED_DIR = ROOT / "data" / "block1" / "generated"
SEMGREP_DIR = ROOT / "data" / "block1" / "semgrep"
RESULTS_DIR = ROOT / "results" / "block1"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

raw_rows = []
sample_rows = []

scenario_condition = defaultdict(
    lambda: {
        "samples": 0,
        "samples_with_findings": 0,
        "raw_findings": 0,
        "normalized_findings": 0,
    }
)

condition_summary = defaultdict(
    lambda: {
        "samples": 0,
        "samples_with_findings": 0,
        "raw_findings": 0,
        "normalized_findings": 0,
    }
)

cwe_summary = defaultdict(
    lambda: {
        "samples": set(),
        "raw_findings": 0
    }
)


def extract_cwes(value):
    """
    Extrae identificadores CWE numéricos de los metadatos
    de Semgrep.

    Ejemplo:
    CWE-78: Improper Neutralization...
    -> CWE-78
    """

    if not value:
        return []

    if isinstance(value, list):
        text = " | ".join(map(str, value))
    else:
        text = str(value)

    return sorted(set(
        re.findall(r"CWE-\d+", text)
    ))


metadata_files = sorted(
    GENERATED_DIR.glob("B1_*.json")
)

for metadata_file in metadata_files:

    metadata = json.loads(
        metadata_file.read_text(
            encoding="utf-8"
        )
    )

    sample_id = metadata["sample_id"]
    scenario_id = metadata["scenario_id"]
    scenario_name = metadata["scenario_name"]
    condition = metadata["condition"]
    repetition = metadata["repetition"]

    semgrep_file = (
        SEMGREP_DIR / f"{sample_id}.json"
    )

    semgrep_data = json.loads(
        semgrep_file.read_text(
            encoding="utf-8"
        )
    )

    findings = semgrep_data.get(
        "results",
        []
    )

    # Para normalización:
    # CWE únicas dentro de cada muestra
    sample_cwes = set()

    severity_counts = defaultdict(int)

    for finding in findings:

        extra = finding.get("extra", {})
        rule_metadata = extra.get(
            "metadata",
            {}
        ) or {}

        severity = extra.get(
            "severity",
            ""
        )

        severity_counts[severity] += 1

        cwes = extract_cwes(
            rule_metadata.get(
                "cwe",
                ""
            )
        )

        owasp = rule_metadata.get(
            "owasp",
            ""
        )

        if isinstance(owasp, list):
            owasp = " | ".join(
                map(str, owasp)
            )

        if not cwes:
            cwe_for_raw = ""
        else:
            cwe_for_raw = " | ".join(cwes)

        raw_rows.append({
            "sample_id": sample_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "condition": condition,
            "repetition": repetition,
            "rule_id":
                finding.get(
                    "check_id",
                    ""
                ),
            "severity": severity,
            "cwe": cwe_for_raw,
            "owasp": owasp,
            "message":
                extra.get(
                    "message",
                    ""
                ),
            "path":
                finding.get(
                    "path",
                    ""
                ),
            "start_line":
                finding.get(
                    "start",
                    {}
                ).get(
                    "line",
                    ""
                ),
        })

        for cwe in cwes:

            sample_cwes.add(cwe)

            cwe_summary[cwe][
                "raw_findings"
            ] += 1

            cwe_summary[cwe][
                "samples"
            ].add(sample_id)

    raw_count = len(findings)
    normalized_count = len(sample_cwes)

    has_findings = (
        1 if raw_count > 0 else 0
    )

    sample_rows.append({
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "condition": condition,
        "repetition": repetition,
        "raw_findings": raw_count,
        "normalized_cwe_findings":
            normalized_count,
        "unique_cwes":
            " | ".join(
                sorted(sample_cwes)
            ),
        "error_findings":
            severity_counts.get(
                "ERROR",
                0
            ),
        "warning_findings":
            severity_counts.get(
                "WARNING",
                0
            ),
        "info_findings":
            severity_counts.get(
                "INFO",
                0
            ),
    })

    key = (
        scenario_id,
        condition
    )

    scenario_condition[key][
        "samples"
    ] += 1

    scenario_condition[key][
        "samples_with_findings"
    ] += has_findings

    scenario_condition[key][
        "raw_findings"
    ] += raw_count

    scenario_condition[key][
        "normalized_findings"
    ] += normalized_count

    condition_summary[condition][
        "samples"
    ] += 1

    condition_summary[condition][
        "samples_with_findings"
    ] += has_findings

    condition_summary[condition][
        "raw_findings"
    ] += raw_count

    condition_summary[condition][
        "normalized_findings"
    ] += normalized_count


# -------------------------------------------------
# 1. HALLAZGOS BRUTOS
# -------------------------------------------------

raw_file = (
    RESULTS_DIR
    / "block1_raw_findings.csv"
)

raw_fields = [
    "sample_id",
    "scenario_id",
    "scenario_name",
    "condition",
    "repetition",
    "rule_id",
    "severity",
    "cwe",
    "owasp",
    "message",
    "path",
    "start_line",
]

with raw_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=raw_fields
    )

    writer.writeheader()
    writer.writerows(raw_rows)


# -------------------------------------------------
# 2. RESUMEN POR MUESTRA
# -------------------------------------------------

sample_file = (
    RESULTS_DIR
    / "block1_samples.csv"
)

sample_fields = [
    "sample_id",
    "scenario_id",
    "scenario_name",
    "condition",
    "repetition",
    "raw_findings",
    "normalized_cwe_findings",
    "unique_cwes",
    "error_findings",
    "warning_findings",
    "info_findings",
]

with sample_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=sample_fields
    )

    writer.writeheader()
    writer.writerows(sample_rows)


# -------------------------------------------------
# 3. RESUMEN ESCENARIO + CONDICION
# -------------------------------------------------

scenario_file = (
    RESULTS_DIR
    / "block1_scenario_condition.csv"
)

scenario_fields = [
    "scenario_id",
    "condition",
    "samples",
    "samples_with_findings",
    "rate_samples_with_findings_pct",
    "raw_findings",
    "normalized_cwe_findings",
    "avg_raw_findings_per_sample",
    "avg_normalized_findings_per_sample",
]

with scenario_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=scenario_fields
    )

    writer.writeheader()

    for (
        scenario_id,
        condition
    ), values in sorted(
        scenario_condition.items()
    ):

        samples = values["samples"]
        affected = values[
            "samples_with_findings"
        ]

        writer.writerow({
            "scenario_id":
                scenario_id,

            "condition":
                condition,

            "samples":
                samples,

            "samples_with_findings":
                affected,

            "rate_samples_with_findings_pct":
                round(
                    affected
                    / samples
                    * 100,
                    2
                ),

            "raw_findings":
                values[
                    "raw_findings"
                ],

            "normalized_cwe_findings":
                values[
                    "normalized_findings"
                ],

            "avg_raw_findings_per_sample":
                round(
                    values[
                        "raw_findings"
                    ]
                    / samples,
                    2
                ),

            "avg_normalized_findings_per_sample":
                round(
                    values[
                        "normalized_findings"
                    ]
                    / samples,
                    2
                ),
        })


# -------------------------------------------------
# 4. RESUMEN POR CONDICION
# -------------------------------------------------

condition_file = (
    RESULTS_DIR
    / "block1_condition_summary.csv"
)

condition_fields = [
    "condition",
    "samples",
    "samples_with_findings",
    "rate_samples_with_findings_pct",
    "raw_findings",
    "normalized_cwe_findings",
    "avg_raw_findings_per_sample",
    "avg_normalized_findings_per_sample",
]

with condition_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=condition_fields
    )

    writer.writeheader()

    for condition, values in sorted(
        condition_summary.items()
    ):

        samples = values["samples"]
        affected = values[
            "samples_with_findings"
        ]

        writer.writerow({
            "condition":
                condition,

            "samples":
                samples,

            "samples_with_findings":
                affected,

            "rate_samples_with_findings_pct":
                round(
                    affected
                    / samples
                    * 100,
                    2
                ),

            "raw_findings":
                values[
                    "raw_findings"
                ],

            "normalized_cwe_findings":
                values[
                    "normalized_findings"
                ],

            "avg_raw_findings_per_sample":
                round(
                    values[
                        "raw_findings"
                    ]
                    / samples,
                    2
                ),

            "avg_normalized_findings_per_sample":
                round(
                    values[
                        "normalized_findings"
                    ]
                    / samples,
                    2
                ),
        })


# -------------------------------------------------
# 5. RESUMEN CWE
# -------------------------------------------------

cwe_file = (
    RESULTS_DIR
    / "block1_cwe_summary.csv"
)

cwe_fields = [
    "cwe",
    "affected_samples",
    "raw_findings",
]

with cwe_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=cwe_fields
    )

    writer.writeheader()

    for cwe, values in sorted(
        cwe_summary.items()
    ):

        writer.writerow({
            "cwe":
                cwe,

            "affected_samples":
                len(
                    values["samples"]
                ),

            "raw_findings":
                values[
                    "raw_findings"
                ],
        })


print("=" * 60)
print("CONSOLIDACION BLOQUE I FINALIZADA")
print("=" * 60)
print("Muestras procesadas :", len(sample_rows))
print("Hallazgos brutos    :", len(raw_rows))
print()
print("Archivos:")
print(raw_file)
print(sample_file)
print(scenario_file)
print(condition_file)
print(cwe_file)
print("=" * 60)