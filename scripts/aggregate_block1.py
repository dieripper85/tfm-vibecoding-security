from pathlib import Path
import json, csv

ROOT = Path(__file__).resolve().parents[1]
gen = ROOT/"data/block1/generated"
sg = ROOT/"data/block1/semgrep"
out = ROOT/"results"
out.mkdir(exist_ok=True)

rows = []
summary = {}

for meta_file in sorted(gen.glob("B1_*.json")):
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    sid = meta["sample_id"]
    semgrep_file = sg/f"{sid}.json"
    findings = []
    if semgrep_file.exists():
        try:
            raw = json.loads(semgrep_file.read_text(encoding="utf-8"))
            findings = raw.get("results", [])
        except Exception:
            findings = []

    key = (meta["scenario_id"], meta["condition"])
    s = summary.setdefault(key, {"samples":0, "samples_with_findings":0, "findings":0})
    s["samples"] += 1
    s["findings"] += len(findings)
    if findings:
        s["samples_with_findings"] += 1

    if not findings:
        rows.append({
            **{k: meta.get(k) for k in ["sample_id","scenario_id","scenario_name","condition","repetition","requested_model","returned_model","executed_at_utc"]},
            "rule_id":"","path":"","line":"","severity":"","message":"","cwe":"","owasp":""
        })
        continue

    for f in findings:
        extra = f.get("extra", {})
        md = extra.get("metadata", {}) or {}
        cwe = md.get("cwe", "")
        owasp = md.get("owasp", "")
        if isinstance(cwe, list): cwe = " | ".join(map(str,cwe))
        if isinstance(owasp, list): owasp = " | ".join(map(str,owasp))
        rows.append({
            **{k: meta.get(k) for k in ["sample_id","scenario_id","scenario_name","condition","repetition","requested_model","returned_model","executed_at_utc"]},
            "rule_id": f.get("check_id",""),
            "path": f.get("path",""),
            "line": (f.get("start") or {}).get("line",""),
            "severity": extra.get("severity",""),
            "message": extra.get("message",""),
            "cwe": cwe,
            "owasp": owasp
        })

fields = ["sample_id","scenario_id","scenario_name","condition","repetition","requested_model","returned_model","executed_at_utc",
          "rule_id","path","line","severity","message","cwe","owasp"]
with (out/"block1_findings.csv").open("w", newline="", encoding="utf-8-sig") as fh:
    w = csv.DictWriter(fh, fieldnames=fields)
    w.writeheader(); w.writerows(rows)

with (out/"block1_summary.csv").open("w", newline="", encoding="utf-8-sig") as fh:
    fields2 = ["scenario_id","condition","samples","samples_with_findings","rate_samples_with_findings_pct","findings","avg_findings_per_sample"]
    w = csv.DictWriter(fh, fieldnames=fields2)
    w.writeheader()
    for (scenario, condition), s in sorted(summary.items()):
        w.writerow({
            "scenario_id":scenario,
            "condition":condition,
            **s,
            "rate_samples_with_findings_pct": round(100*s["samples_with_findings"]/s["samples"],2) if s["samples"] else 0,
            "avg_findings_per_sample": round(s["findings"]/s["samples"],3) if s["samples"] else 0
        })
print("Generados:", out/"block1_findings.csv", "y", out/"block1_summary.csv")
