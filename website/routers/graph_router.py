from fastapi import APIRouter, Query
from typing import Optional

from services.graph_builder import build_graph

router = APIRouter()

_TYPES = {"ip", "domain", "email", "hash", "cve", "onion", "wallet"}


@router.get("/graph")
async def get_graph(
    type: Optional[str] = Query(None),
    agent: Optional[str] = Query(None),
    days: Optional[int] = Query(None),
):
    itype = type if type in _TYPES else None
    return build_graph(itype, agent, days)
