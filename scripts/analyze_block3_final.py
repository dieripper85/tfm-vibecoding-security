from pathlib import Path
from collections import Counter, defaultdict
import csv
import json
import re


ROOT = Path(__file__).resolve().parents[1]

MANIFEST_FILE = (
    ROOT / "results" / "block3" / "block3_manifest.csv"
)

PRE_FILE = (
    ROOT / "results" / "block1" / "block1_findings_classified.csv"
)

POST_DIR = (
    ROOT / "data" / "block3" / "semgrep_post"
)

RESULTS_DIR = (
    ROOT / "results" / "block3"
)

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def text_value(value):

    if value is None:
        return ""

    if isinstance(value, list):
        return " | ".join(
            str(x) for x in value
        )

    if isinstance(value, dict):
        return json.dumps(
            value,
            ensure_ascii=False
        )

    return str(value)


def extract_cwes(value):

    text = text_value(value).upper()

    return sorted(
        set(
            re.findall(
                r"CWE-\d+",
                text
            )
        )
    )


def classify_scope(
    rule_id,
    cwes
):

    rule = rule_id.lower()

    # Mismo criterio utilizado
    # en el Bloque I.
    if ".maintainability." in rule:
        return "QUALITY"

    if (
        cwes
        or ".security." in rule
    ):
        return "SECURITY"

    return "OTHER"


def pct_reduction(pre, post):

    if pre == 0:
        return 0.0

    return round(
        ((pre - post) / pre)
        * 100,
        2
    )


# ==================================================
# MANIFEST BLOQUE III
# ==================================================

with MANIFEST_FILE.open(
    encoding="utf-8-sig"
) as f:

    manifest_rows = list(
        csv.DictReader(f)
    )


manifest = {
    row["sample_id"]: row
    for row in manifest_rows
}


# ==================================================
# HALLAZGOS PRE - BLOQUE I
# ==================================================

with PRE_FILE.open(
    encoding="utf-8-sig"
) as f:

    pre_all_rows = list(
        csv.DictReader(f)
    )


pre_security_rows = [
    row
    for row in pre_all_rows
    if row.get(
        "scope",
        ""
    ).strip().upper()
    == "SECURITY"
]


pre_by_sample = defaultdict(list)

for row in pre_security_rows:

    sample_id = row.get(
        "sample_id",
        ""
    ).strip()

    if sample_id in manifest:
        pre_by_sample[
            sample_id
        ].append(row)


# ==================================================
# HALLAZGOS POST
# ==================================================

post_rows = []


for json_file in sorted(
    POST_DIR.glob("*.json")
):

    sample_id = (
        json_file.stem
    )

    if sample_id not in manifest:
        raise RuntimeError(
            f"{sample_id} no está "
            "en el manifest del Bloque III"
        )

    meta_sample = manifest[
        sample_id
    ]

    data = json.loads(
        json_file.read_text(
            encoding="utf-8"
        )
    )

    for finding_number, result in enumerate(
        data.get("results", []),
        start=1
    ):

        extra = (
            result.get(
                "extra",
                {}
            )
            or {}
        )

        metadata = (
            extra.get(
                "metadata",
                {}
            )
            or {}
        )

        rule_id = result.get(
            "check_id",
            ""
        )

        cwes = extract_cwes(
            metadata.get("cwe")
        )

        owasp = text_value(
            metadata.get("owasp")
        )

        scope = classify_scope(
            rule_id,
            cwes
        )

        start = (
            result.get(
                "start",
                {}
            )
            or {}
        )

        post_rows.append({

            "sample_id":
                sample_id,

            "scenario":
                meta_sample.get(
                    "scenario",
                    ""
                ),

            "condition":
                meta_sample.get(
                    "condition",
                    ""
                ),

            "finding_number":
                finding_number,

            "rule_id":
                rule_id,

            "scope":
                scope,

            "cwe":
                " | ".join(cwes),

            "owasp":
                owasp,

            "severity":
                extra.get(
                    "severity",
                    ""
                ),

            "line":
                start.get(
                    "line",
                    ""
                ),

            "message":
                extra.get(
                    "message",
                    ""
                ),

            "path":
                result.get(
                    "path",
                    ""
                ),
        })


# ==================================================
# EXPORTAR HALLAZGOS POST CLASIFICADOS
# ==================================================

post_findings_file = (
    RESULTS_DIR
    / "block3_post_findings_classified.csv"
)

post_fields = [
    "sample_id",
    "scenario",
    "condition",
    "finding_number",
    "rule_id",
    "scope",
    "cwe",
    "owasp",
    "severity",
    "line",
    "message",
    "path",
]


with post_findings_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=post_fields
    )

    writer.writeheader()
    writer.writerows(
        post_rows
    )


# ==================================================
# RESUMEN DE SCOPE POST
# ==================================================

scope_counts = Counter(
    row["scope"]
    for row in post_rows
)

scope_file = (
    RESULTS_DIR
    / "block3_post_scope_summary.csv"
)


with scope_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "scope",
            "findings"
        ]
    )

    writer.writeheader()

    for scope in [
        "SECURITY",
        "QUALITY",
        "OTHER"
    ]:

        writer.writerow({
            "scope":
                scope,

            "findings":
                scope_counts.get(
                    scope,
                    0
                ),
        })


# ==================================================
# SOLO SECURITY POST
# ==================================================

post_security_rows = [
    row
    for row in post_rows
    if row["scope"]
    == "SECURITY"
]


post_security_by_sample = (
    defaultdict(list)
)

for row in post_security_rows:

    post_security_by_sample[
        row["sample_id"]
    ].append(row)


# ==================================================
# COMPARACIÓN POR MUESTRA
# ==================================================

sample_comparison = []


for sample_id in sorted(
    manifest
):

    metadata = manifest[
        sample_id
    ]

    pre_rows = pre_by_sample.get(
        sample_id,
        []
    )

    post_sec_rows = (
        post_security_by_sample.get(
            sample_id,
            []
        )
    )

    pre_count = len(
        pre_rows
    )

    post_count = len(
        post_sec_rows
    )


    pre_cwes = set()

    for row in pre_rows:
        pre_cwes.update(
            extract_cwes(
                row.get(
                    "cwe",
                    ""
                )
            )
        )


    post_cwes = set()

    for row in post_sec_rows:
        post_cwes.update(
            extract_cwes(
                row.get(
                    "cwe",
                    ""
                )
            )
        )


    persistent = (
        pre_cwes
        & post_cwes
    )

    eliminated = (
        pre_cwes
        - post_cwes
    )

    new = (
        post_cwes
        - pre_cwes
    )


    if post_count == 0:

        status = (
            "FULLY_REMEDIATED"
        )

    elif post_count < pre_count:

        status = (
            "PARTIAL_REDUCTION"
        )

    elif post_count == pre_count:

        status = (
            "UNCHANGED_COUNT"
        )

    else:

        status = (
            "INCREASED"
        )


    sample_comparison.append({

        "sample_id":
            sample_id,

        "scenario":
            metadata.get(
                "scenario",
                ""
            ),

        "condition":
            metadata.get(
                "condition",
                ""
            ),

        "pre_security_findings":
            pre_count,

        "post_security_findings":
            post_count,

        "finding_difference":
            post_count
            - pre_count,

        "reduction_pct":
            pct_reduction(
                pre_count,
                post_count
            ),

        "pre_cwes":
            " | ".join(
                sorted(
                    pre_cwes
                )
            ),

        "post_cwes":
            " | ".join(
                sorted(
                    post_cwes
                )
            ),

        "persistent_cwes":
            " | ".join(
                sorted(
                    persistent
                )
            ),

        "eliminated_cwes":
            " | ".join(
                sorted(
                    eliminated
                )
            ),

        "new_cwes":
            " | ".join(
                sorted(
                    new
                )
            ),

        "status":
            status,
    })


sample_file = (
    RESULTS_DIR
    / "block3_sample_comparison.csv"
)


sample_fields = list(
    sample_comparison[0].keys()
)


with sample_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=sample_fields
    )

    writer.writeheader()
    writer.writerows(
        sample_comparison
    )


# ==================================================
# FUNCIÓN PARA RESÚMENES
# ==================================================

def build_group_summary(
    field_name
):

    grouped = defaultdict(list)

    for row in sample_comparison:

        grouped[
            row[field_name]
        ].append(row)


    output = []

    for group, rows in sorted(
        grouped.items()
    ):

        pre = sum(
            int(
                row[
                    "pre_security_findings"
                ]
            )
            for row in rows
        )

        post = sum(
            int(
                row[
                    "post_security_findings"
                ]
            )
            for row in rows
        )

        fully = sum(
            1
            for row in rows
            if row["status"]
            == "FULLY_REMEDIATED"
        )

        increased = sum(
            1
            for row in rows
            if row["status"]
            == "INCREASED"
        )

        output.append({

            field_name:
                group,

            "samples":
                len(rows),

            "pre_security_findings":
                pre,

            "post_security_findings":
                post,

            "absolute_reduction":
                pre - post,

            "reduction_pct":
                pct_reduction(
                    pre,
                    post
                ),

            "fully_remediated_samples":
                fully,

            "residual_samples":
                len(rows)
                - fully,

            "increased_samples":
                increased,
        })


    return output


# ==================================================
# RESUMEN POR CONDICIÓN
# ==================================================

condition_rows = (
    build_group_summary(
        "condition"
    )
)

condition_file = (
    RESULTS_DIR
    / "block3_condition_summary.csv"
)

with condition_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(
            condition_rows[0].keys()
        )
    )

    writer.writeheader()
    writer.writerows(
        condition_rows
    )


# ==================================================
# RESUMEN POR ESCENARIO
# ==================================================

scenario_rows = (
    build_group_summary(
        "scenario"
    )
)

scenario_file = (
    RESULTS_DIR
    / "block3_scenario_summary.csv"
)

with scenario_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(
            scenario_rows[0].keys()
        )
    )

    writer.writeheader()
    writer.writerows(
        scenario_rows
    )


# ==================================================
# COMPARACIÓN POR CWE
# ==================================================

pre_cwe_raw = Counter()
post_cwe_raw = Counter()

pre_cwe_samples = defaultdict(set)
post_cwe_samples = defaultdict(set)


for row in pre_security_rows:

    sample_id = row.get(
        "sample_id",
        ""
    ).strip()

    if sample_id not in manifest:
        continue

    for cwe in extract_cwes(
        row.get(
            "cwe",
            ""
        )
    ):

        pre_cwe_raw[cwe] += 1

        pre_cwe_samples[
            cwe
        ].add(
            sample_id
        )


for row in post_security_rows:

    sample_id = row[
        "sample_id"
    ]

    for cwe in extract_cwes(
        row["cwe"]
    ):

        post_cwe_raw[
            cwe
        ] += 1

        post_cwe_samples[
            cwe
        ].add(
            sample_id
        )


all_cwes = sorted(
    set(
        pre_cwe_raw
    )
    | set(
        post_cwe_raw
    )
)


cwe_rows = []

for cwe in all_cwes:

    pre = pre_cwe_raw.get(
        cwe,
        0
    )

    post = post_cwe_raw.get(
        cwe,
        0
    )

    if pre > 0 and post == 0:
        status = "ELIMINATED"

    elif pre > 0 and post > 0:
        status = "PERSISTENT"

    else:
        status = "NEW"


    cwe_rows.append({

        "cwe":
            cwe,

        "pre_raw_findings":
            pre,

        "post_raw_findings":
            post,

        "difference":
            post - pre,

        "reduction_pct":
            pct_reduction(
                pre,
                post
            )
            if pre else "",

        "pre_affected_samples":
            len(
                pre_cwe_samples.get(
                    cwe,
                    set()
                )
            ),

        "post_affected_samples":
            len(
                post_cwe_samples.get(
                    cwe,
                    set()
                )
            ),

        "status":
            status,
    })


cwe_file = (
    RESULTS_DIR
    / "block3_cwe_comparison.csv"
)


with cwe_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(
            cwe_rows[0].keys()
        )
    )

    writer.writeheader()
    writer.writerows(
        cwe_rows
    )


# ==================================================
# RESUMEN GLOBAL
# ==================================================

pre_total = len(
    pre_security_rows
)

post_security_total = len(
    post_security_rows
)

post_all_total = len(
    post_rows
)

fully_remediated = sum(
    1
    for row in sample_comparison
    if row["status"]
    == "FULLY_REMEDIATED"
)

partial = sum(
    1
    for row in sample_comparison
    if row["status"]
    == "PARTIAL_REDUCTION"
)

unchanged = sum(
    1
    for row in sample_comparison
    if row["status"]
    == "UNCHANGED_COUNT"
)

increased = sum(
    1
    for row in sample_comparison
    if row["status"]
    == "INCREASED"
)


pre_unique_cwes = set(
    pre_cwe_raw
)

post_unique_cwes = set(
    post_cwe_raw
)


global_row = {

    "samples":
        len(
            sample_comparison
        ),

    "pre_security_findings":
        pre_total,

    "post_all_raw_findings":
        post_all_total,

    "post_security_findings":
        post_security_total,

    "post_quality_findings":
        scope_counts.get(
            "QUALITY",
            0
        ),

    "post_other_findings":
        scope_counts.get(
            "OTHER",
            0
        ),

    "security_absolute_reduction":
        pre_total
        - post_security_total,

    "security_reduction_pct":
        pct_reduction(
            pre_total,
            post_security_total
        ),

    "fully_remediated_samples":
        fully_remediated,

    "fully_remediated_rate_pct":
        round(
            fully_remediated
            / len(
                sample_comparison
            )
            * 100,
            2
        ),

    "residual_samples":
        len(
            sample_comparison
        )
        - fully_remediated,

    "partial_reduction_samples":
        partial,

    "unchanged_count_samples":
        unchanged,

    "increased_samples":
        increased,

    "pre_unique_cwes":
        " | ".join(
            sorted(
                pre_unique_cwes
            )
        ),

    "post_unique_cwes":
        " | ".join(
            sorted(
                post_unique_cwes
            )
        ),

    "eliminated_cwe_categories":
        " | ".join(
            sorted(
                pre_unique_cwes
                - post_unique_cwes
            )
        ),

    "persistent_cwe_categories":
        " | ".join(
            sorted(
                pre_unique_cwes
                & post_unique_cwes
            )
        ),

    "new_cwe_categories":
        " | ".join(
            sorted(
                post_unique_cwes
                - pre_unique_cwes
            )
        ),
}


global_file = (
    RESULTS_DIR
    / "block3_global_summary.csv"
)


with global_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(
            global_row.keys()
        )
    )

    writer.writeheader()
    writer.writerow(
        global_row
    )


# ==================================================
# SALIDA CONSOLA
# ==================================================

print("=" * 60)
print("ANALISIS BLOQUE III FINALIZADO")
print("=" * 60)

print(
    "Muestras                     :",
    global_row["samples"]
)

print(
    "Security findings PRE        :",
    pre_total
)

print(
    "Raw findings POST            :",
    post_all_total
)

print(
    "Security findings POST       :",
    post_security_total
)

print(
    "Quality findings POST        :",
    global_row[
        "post_quality_findings"
    ]
)

print(
    "Other findings POST          :",
    global_row[
        "post_other_findings"
    ]
)

print(
    "Reduccion SECURITY           :",
    f"{global_row['security_reduction_pct']}%"
)

print(
    "Muestras totalmente corregidas:",
    fully_remediated
)

print(
    "Muestras con residuales      :",
    global_row[
        "residual_samples"
    ]
)

print(
    "Muestras con incremento      :",
    increased
)

print("=" * 60)