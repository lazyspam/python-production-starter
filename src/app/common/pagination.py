from dataclasses import dataclass
from math import ceil
from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class PageParams:
    page: Annotated[int, Query(ge=1)] = 1
    limit: Annotated[int, Query(ge=1, le=150)] = 10


Page = Annotated[PageParams, Depends()]


async def paginate(db: AsyncSession, stmt: Select, params: PageParams) -> tuple[list, dict]:
    """Offset pagination over a select of one entity. Returns the rows and the `meta` block."""
    total = await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = (await db.scalars(stmt.offset((params.page - 1) * params.limit).limit(params.limit))).all()
    pages = ceil(total / params.limit)
    meta = {
        "mode": "offset", "total": total, "page": params.page, "limit": params.limit,
        "totalPages": pages, "hasNext": params.page < pages, "hasPrev": params.page > 1,
    }  # fmt: skip
    return list(rows), meta
