from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from services.report_parser import list_reports, read_report, delete_report

router = APIRouter()


@router.get("/reports")
async def get_reports(q: str = Query(None)):
    reports = list_reports()
    if q:
        q_lower = q.lower()
        matched = []
        for r in reports:
            content = read_report(r["filename"]) or ""
            if q_lower in r["filename"].lower() or q_lower in content.lower():
                matched.append(r)
        return matched
    return reports


@router.get("/reports/{filename:path}", response_class=PlainTextResponse)
async def get_report(filename: str):
    content = read_report(filename)
    if content is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return content


@router.delete("/reports/{filename:path}")
async def del_report(filename: str):
    ok = delete_report(filename)
    if not ok:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"deleted": filename}
