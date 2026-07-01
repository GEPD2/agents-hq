import asyncio
import re
import uuid
from datetime import datetime
from pathlib import Path

from services.log_streamer import spawn_agent, stream_job
from services.report_parser import REPORTS_DIR

# batch_id -> {targets, mode, index, total, results, queue, done, started}
_batches: dict[str, dict] = {}

_TARGET_RE = re.compile(r'^[A-Za-z0-9 ./:_@?=&%+,\-\[\]{}#!*]+$')
_TARGET_MAX_LEN = 512
_MAX_TARGETS = 100
_ALLOWED_MODES = {"adaptive", "fast", "deep"}


def parse_targets(raw: str) -> list[str]:
    """Split pasted text / uploaded file into a clean, deduped target list."""
    seen = []
    for line in raw.replace(",", "\n").splitlines():
        t = line.strip()
        if not t:
            continue
        if len(t) > _TARGET_MAX_LEN or not _TARGET_RE.match(t):
            continue
        if t not in seen:
            seen.append(t)
        if len(seen) >= _MAX_TARGETS:
            break
    return seen


def _newest_report_since(since_ts: float) -> str | None:
    if not REPORTS_DIR.exists():
        return None
    candidates = [f for f in REPORTS_DIR.glob("*.md") if f.stat().st_mtime >= since_ts]
    if not candidates:
        return None
    return max(candidates, key=lambda f: f.stat().st_mtime).name


async def _run_one(batch_id: str, target: str, mode: str, q: asyncio.Queue) -> dict:
    started = datetime.utcnow().timestamp()
    result = {"target": target, "report": None, "status": "error"}
    try:
        job_id = await spawn_agent("01", {"target": target, "mode": mode})
    except Exception as e:
        await q.put(f"[ERROR] {target}: {e}")
        return result

    async for chunk in stream_job(job_id):
        if not chunk.startswith("data: "):
            continue
        line = chunk[6:].rstrip("\n")
        if line == "[HEARTBEAT]":
            continue
        if line == "[DONE]":
            break
        await q.put(f"[{target}] {line}")

    report = _newest_report_since(started)
    result["report"] = report
    result["status"] = "done" if report else "no-report"
    return result


def _write_summary(batch_id: str, batch: dict) -> str | None:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"BATCH_OSINT_{batch_id}_{ts}.md"
    lines = [
        f"# Batch OSINT Summary — {batch_id}",
        "",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        f"Mode: {batch['mode']}",
        f"Targets: {batch['total']}",
        "",
        "## Results",
        "",
        "| # | Target | Status | Report |",
        "|---|--------|--------|--------|",
    ]
    for i, r in enumerate(batch["results"], 1):
        link = f"[{r['report']}](/reports/{r['report']})" if r.get("report") else "—"
        lines.append(f"| {i} | {r['target']} | {r['status']} | {link} |")
    try:
        path = REPORTS_DIR / filename
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return filename
    except Exception:
        return None


async def _run_batch(batch_id: str):
    batch = _batches[batch_id]
    q = batch["queue"]
    for i, target in enumerate(batch["targets"]):
        batch["index"] = i
        await q.put(f"[BATCH] ({i + 1}/{batch['total']}) starting {target}")
        result = await _run_one(batch_id, target, batch["mode"], q)
        batch["results"].append(result)
        await q.put(f"[BATCH] ({i + 1}/{batch['total']}) {target} -> {result['status']}")
    batch["index"] = batch["total"]
    summary = _write_summary(batch_id, batch)
    batch["summary"] = summary
    if summary:
        await q.put(f"[BATCH] summary report: {summary}")
    batch["done"] = True
    await q.put("[DONE]")


def start_batch(targets: list[str], mode: str = "adaptive") -> dict:
    if mode not in _ALLOWED_MODES:
        mode = "adaptive"
    batch_id = str(uuid.uuid4())[:8]
    _batches[batch_id] = {
        "targets": targets,
        "mode": mode,
        "index": 0,
        "total": len(targets),
        "results": [],
        "queue": asyncio.Queue(),
        "done": False,
        "summary": None,
        "started": datetime.utcnow().isoformat(),
    }
    asyncio.create_task(_run_batch(batch_id))
    return {"batch_id": batch_id, "total": len(targets)}


def batch_status(batch_id: str) -> dict | None:
    b = _batches.get(batch_id)
    if not b:
        return None
    return {
        "batch_id": batch_id,
        "total": b["total"],
        "completed": len(b["results"]),
        "index": b["index"],
        "done": b["done"],
        "summary": b["summary"],
        "results": b["results"],
    }


async def stream_batch(batch_id: str):
    b = _batches.get(batch_id)
    if not b:
        yield "data: [ERROR] Batch not found\n\n"
        yield "data: [DONE]\n\n"
        return
    q = b["queue"]
    while True:
        try:
            line = await asyncio.wait_for(q.get(), timeout=60.0)
            yield f"data: {line}\n\n"
            if line == "[DONE]":
                break
        except asyncio.TimeoutError:
            yield "data: [HEARTBEAT]\n\n"
