import io
import zipfile
from datetime import datetime
from pathlib import Path

from services.report_parser import read_report


def build_case_zip(case: dict) -> bytes:
    """Package a case into a ZIP: overview, auto-brief, and all linked report files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        overview = _overview_md(case)
        zf.writestr("case_overview.md", overview)

        if case.get("brief"):
            zf.writestr("auto_brief.md", case["brief"])

        for it in case.get("items", []):
            if it["item_type"] != "report":
                continue
            content = read_report(it["ref"])
            if content:
                # basename only - prevent zip-slip via crafted item ref
                safe_name = Path(it["ref"]).name
                zf.writestr(f"reports/{safe_name}", content)

    return buf.getvalue()


def _overview_md(case: dict) -> str:
    lines = [
        f"# Case: {case.get('name', 'Untitled')}",
        "",
        f"Exported: {datetime.utcnow().isoformat()}Z",
        f"Case ID: {case.get('id', '')}",
        f"Tags: {case.get('tags', '') or '—'}",
        "",
        "## Description",
        "",
        case.get("description") or "_No description_",
        "",
        "## Linked Items",
        "",
        "| Type | Reference | Label |",
        "|------|-----------|-------|",
    ]
    for it in case.get("items", []):
        lines.append(f"| {it['item_type']} | {it['ref']} | {it.get('label', '') or '—'} |")
    return "\n".join(lines) + "\n"
