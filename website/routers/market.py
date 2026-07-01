from fastapi import APIRouter, Query
from typing import Optional

from services.market_correlator import build_correlation

router = APIRouter()


@router.get("/market/correlation")
async def market_correlation(
    tickers: Optional[str] = Query(None),
    days: int = Query(90),
):
    ticker_list = [t for t in (tickers.split(",") if tickers else []) if t.strip()]
    if days not in (30, 90, 180, 365):
        days = 90
    return build_correlation(ticker_list or None, days)
