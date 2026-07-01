from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional

from services import case_store
from services.case_exporter import build_case_zip
from services.ollama import chat
from services.report_parser import read_report

router = APIRouter()


class CaseCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    tags: Optional[str] = ""


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[str] = None


class ItemAdd(BaseModel):
    item_type: str
    ref: str
    label: Optional[str] = ""


@router.get("/cases")
async def get_cases():
    return case_store.list_cases()


@router.post("/cases")
async def post_case(body: CaseCreate):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Case name is required")
    case_id = case_store.create_case(body.name.strip(), body.description or "", body.tags or "")
    return {"id": case_id}


@router.get("/cases/{case_id}")
async def get_case(case_id: str):
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}")
async def patch_case(case_id: str, body: CaseUpdate):
    ok = case_store.update_case(case_id, body.name, body.description, body.tags)
    return {"updated": ok}


@router.delete("/cases/{case_id}")
async def del_case(case_id: str):
    return {"deleted": case_store.delete_case(case_id)}


@router.post("/cases/{case_id}/items")
async def add_case_item(case_id: str, body: ItemAdd):
    item_id = case_store.add_item(case_id, body.item_type, body.ref, body.label or "")
    if item_id is None:
        raise HTTPException(status_code=400, detail="Invalid item")
    return {"id": item_id}


@router.delete("/cases/{case_id}/items/{item_id}")
async def del_case_item(case_id: str, item_id: str):
    return {"removed": case_store.remove_item(case_id, item_id)}


@router.post("/cases/{case_id}/brief")
async def generate_brief(case_id: str):
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    context = _build_context(case)
    messages = [
        {"role": "system", "content":
            "You are a cyber threat intelligence analyst. Write a concise consolidated "
            "intelligence brief in markdown. Include an executive summary, key findings, "
            "linked indicators, and recommended next actions. Be factual and terse."},
        {"role": "user", "content":
            f"Case: {case['name']}\nDescription: {case.get('description') or 'n/a'}\n\n"
            f"Linked intelligence:\n{context}"},
    ]
    brief = chat(messages)
    if brief.startswith("[OLLAMA] Error"):
        brief = _fallback_brief(case, context)
    case_store.save_brief(case_id, brief)
    return {"brief": brief}


@router.get("/cases/{case_id}/export")
async def export_case(case_id: str):
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    data = build_case_zip(case)
    safe = "".join(c for c in case["name"] if c.isalnum() or c in "-_") or case_id
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="case_{safe}.zip"'},
    )


def _build_context(case: dict) -> str:
    parts = []
    for it in case.get("items", []):
        if it["item_type"] == "report":
            content = read_report(it["ref"]) or ""
            parts.append(f"### Report: {it['ref']}\n{content[:4000]}")
        else:
            parts.append(f"### {it['item_type']}: {it['ref']} {it.get('label') or ''}")
    return "\n\n".join(parts) if parts else "No linked items."


def _fallback_brief(case: dict, context: str) -> str:
    items = case.get("items", [])
    lines = [
        f"# {case['name']} — Consolidated Brief",
        "",
        "_Auto-generated (Ollama offline — template fallback)_",
        "",
        "## Description",
        case.get("description") or "_None_",
        "",
        f"## Linked Items ({len(items)})",
    ]
    for it in items:
        lines.append(f"- **{it['item_type']}**: {it['ref']} {it.get('label') or ''}")
    return "\n".join(lines)
