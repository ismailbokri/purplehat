"""CRUD endpoints for checklist_tests.

  GET    /checklist             — any authenticated user (read-only)
  GET    /checklist/categories  — list of distinct categories in order
  POST   /checklist             — admin only
  PUT    /checklist/{id}        — admin only
  DELETE /checklist/{id}        — admin only
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auth.dependencies import CurrentUser, get_current_user, require_admin
from db.connection import get_dict_cursor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/checklist", tags=["checklist"])


# ── Models ────────────────────────────────────────────────────────────────────

class ChecklistTestOut(BaseModel):
    id:                       int
    test_id:                  str
    category:                 str
    tests:                    str
    outils:                   str = ""
    commande:                 str = ""
    ref_procedure:            str = ""
    commentaires:             str = ""
    resultat_attendu:         str = ""
    vulnerabilite_attendue:   str = ""
    bonne_pratique_attendu:   str = ""
    extra:                    Dict[str, Any] = Field(default_factory=dict)
    position:                 int = 0


class ChecklistTestCreate(BaseModel):
    test_id:                  str = Field(min_length=1, max_length=64)
    category:                 str = Field(min_length=1, max_length=128)
    tests:                    str = Field(min_length=1)
    outils:                   str = ""
    commande:                 str = ""
    ref_procedure:            str = ""
    commentaires:             str = ""
    resultat_attendu:         str = ""
    vulnerabilite_attendue:   str = ""
    bonne_pratique_attendu:   str = ""
    extra:                    Dict[str, Any] = Field(default_factory=dict)
    position:                 Optional[int] = None  # auto-assigned at end if None


class ChecklistTestUpdate(BaseModel):
    test_id:                  Optional[str] = None
    category:                 Optional[str] = None
    tests:                    Optional[str] = None
    outils:                   Optional[str] = None
    commande:                 Optional[str] = None
    ref_procedure:            Optional[str] = None
    commentaires:             Optional[str] = None
    resultat_attendu:         Optional[str] = None
    vulnerabilite_attendue:   Optional[str] = None
    bonne_pratique_attendu:   Optional[str] = None
    extra:                    Optional[Dict[str, Any]] = None
    position:                 Optional[int] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_out(row) -> ChecklistTestOut:
    extra = row["extra"] or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    return ChecklistTestOut(
        id=row["id"],
        test_id=row["test_id"],
        category=row["category"],
        tests=row["tests"],
        outils=row["outils"] or "",
        commande=row["commande"] or "",
        ref_procedure=row["ref_procedure"] or "",
        commentaires=row["commentaires"] or "",
        resultat_attendu=row["resultat_attendu"] or "",
        vulnerabilite_attendue=row["vulnerabilite_attendue"] or "",
        bonne_pratique_attendu=row["bonne_pratique_attendu"] or "",
        extra=extra if isinstance(extra, dict) else {},
        position=int(row["position"] or 0),
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[ChecklistTestOut])
def list_tests(_: CurrentUser = Depends(get_current_user)) -> List[ChecklistTestOut]:
    with get_dict_cursor() as cur:
        # Preserve original category order (= order in which they were first inserted)
        # and order tests within a category by position.
        cur.execute(
            """
            WITH cat_order AS (
                SELECT category, MIN(id) AS first_id
                  FROM checklist_tests
                 GROUP BY category
            )
            SELECT t.id, t.test_id, t.category, t.tests, t.outils, t.commande,
                   t.ref_procedure, t.commentaires, t.resultat_attendu,
                   t.vulnerabilite_attendue, t.bonne_pratique_attendu,
                   t.extra, t.position
              FROM checklist_tests t
              JOIN cat_order c ON c.category = t.category
             ORDER BY c.first_id, t.position, t.id
            """
        )
        return [_row_to_out(r) for r in cur.fetchall()]


@router.get("/categories", response_model=List[str])
def list_categories(_: CurrentUser = Depends(get_current_user)) -> List[str]:
    with get_dict_cursor() as cur:
        cur.execute(
            """
            SELECT category, MIN(id) AS first_id
              FROM checklist_tests
             GROUP BY category
             ORDER BY first_id
            """
        )
        return [r["category"] for r in cur.fetchall()]


@router.post("", response_model=ChecklistTestOut, status_code=status.HTTP_201_CREATED)
def create_test(
    payload: ChecklistTestCreate,
    _admin: CurrentUser = Depends(require_admin),
) -> ChecklistTestOut:
    with get_dict_cursor() as cur:
        position = payload.position
        if position is None:
            cur.execute(
                "SELECT COALESCE(MAX(position), 0) + 1 AS p FROM checklist_tests WHERE category = %s",
                (payload.category,),
            )
            position = int(cur.fetchone()["p"])
        cur.execute(
            """
            INSERT INTO checklist_tests
                (test_id, category, tests, outils, commande, ref_procedure,
                 commentaires, resultat_attendu, vulnerabilite_attendue,
                 bonne_pratique_attendu, extra, position)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
            RETURNING id, test_id, category, tests, outils, commande, ref_procedure,
                      commentaires, resultat_attendu, vulnerabilite_attendue,
                      bonne_pratique_attendu, extra, position
            """,
            (
                payload.test_id, payload.category, payload.tests,
                payload.outils, payload.commande, payload.ref_procedure,
                payload.commentaires, payload.resultat_attendu,
                payload.vulnerabilite_attendue, payload.bonne_pratique_attendu,
                json.dumps(payload.extra or {}, ensure_ascii=False),
                position,
            ),
        )
        return _row_to_out(cur.fetchone())


_UPDATABLE_COLUMNS = {
    "test_id", "category", "tests", "outils", "commande", "ref_procedure",
    "commentaires", "resultat_attendu", "vulnerabilite_attendue",
    "bonne_pratique_attendu", "position",
}


@router.put("/{test_db_id}", response_model=ChecklistTestOut)
def update_test(
    test_db_id: int,
    payload: ChecklistTestUpdate,
    _admin: CurrentUser = Depends(require_admin),
) -> ChecklistTestOut:
    updates = payload.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")

    set_clauses: List[str] = []
    values: List[Any] = []
    for col, val in updates.items():
        if col == "extra":
            set_clauses.append("extra = %s::jsonb")
            values.append(json.dumps(val or {}, ensure_ascii=False))
        elif col in _UPDATABLE_COLUMNS:
            set_clauses.append(f"{col} = %s")
            values.append(val)

    if not set_clauses:
        raise HTTPException(status_code=400, detail="No updatable fields provided")

    set_clauses.append("updated_at = now()")
    values.append(test_db_id)

    sql = (
        "UPDATE checklist_tests SET "
        + ", ".join(set_clauses)
        + " WHERE id = %s "
        + " RETURNING id, test_id, category, tests, outils, commande, ref_procedure,"
        + "          commentaires, resultat_attendu, vulnerabilite_attendue,"
        + "          bonne_pratique_attendu, extra, position"
    )
    with get_dict_cursor() as cur:
        cur.execute(sql, values)
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Test not found")
        return _row_to_out(row)


@router.delete("/{test_db_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_test(
    test_db_id: int,
    _admin: CurrentUser = Depends(require_admin),
) -> None:
    with get_dict_cursor() as cur:
        cur.execute("DELETE FROM checklist_tests WHERE id = %s", (test_db_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Test not found")
    return None
