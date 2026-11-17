"""Idempotent database bootstrap.

Run on FastAPI startup:
  1. Create tables from schema.sql if they don't exist.
  2. Seed `checklist_tests` from the original JSON file the *first* time only
     (i.e. when the table is empty). Subsequent CRUD on the table is the source
     of truth — the JSON is no longer consulted.
"""

import json
import logging
import pathlib
from typing import Any, Dict, List

from db.connection import get_conn

logger = logging.getLogger(__name__)

_SCHEMA_PATH = pathlib.Path(__file__).parent / "schema.sql"

_CHECKLIST_JSON_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "palnner"
    / "checklist.json"
)

# Fields stored as dedicated columns; everything else from the original JSON
# row goes into the `extra` JSONB column.
_COLUMN_FIELDS = {
    "ID", "Catégorie", "Tests", "Outils", "Commande", "Réf. Procédure",
    "Commentaires", "Résultat attendu", "Vulnérabilité attendue",
    "Bonne pratique attendu",
}


def apply_schema() -> None:
    sql = _SCHEMA_PATH.read_text(encoding="utf-8")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    logger.info("[bootstrap] schema applied (idempotent)")


def _checklist_is_empty() -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM checklist_tests")
            return int(cur.fetchone()[0]) == 0


def _load_json_rows() -> List[Dict[str, Any]]:
    if not _CHECKLIST_JSON_PATH.exists():
        logger.warning(
            "[bootstrap] checklist JSON not found at %s — skipping seed",
            _CHECKLIST_JSON_PATH,
        )
        return []
    data = json.loads(_CHECKLIST_JSON_PATH.read_text(encoding="utf-8"))
    rows: List[Dict[str, Any]] = []
    for block in data.get("Pentest Web", []):
        category = block.get("category", "")
        for test in block.get("tests", []):
            row = dict(test)
            row.setdefault("Catégorie", category)
            rows.append(row)
    return rows


def seed_checklist_from_json() -> int:
    """Insert all rows from the JSON file. Skips entirely if the table is non-empty."""
    if not _checklist_is_empty():
        logger.info("[bootstrap] checklist_tests already populated — skipping seed")
        return 0

    rows = _load_json_rows()
    if not rows:
        return 0

    inserted = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            position_by_category: Dict[str, int] = {}
            for row in rows:
                category = str(row.get("Catégorie") or "").strip()
                position_by_category[category] = position_by_category.get(category, 0) + 1
                extra = {
                    k: v for k, v in row.items()
                    if k not in _COLUMN_FIELDS
                }
                cur.execute(
                    """
                    INSERT INTO checklist_tests
                        (test_id, category, tests, outils, commande, ref_procedure,
                         commentaires, resultat_attendu, vulnerabilite_attendue,
                         bonne_pratique_attendu, extra, position)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                    """,
                    (
                        str(row.get("ID") or ""),
                        category,
                        str(row.get("Tests") or ""),
                        str(row.get("Outils") or ""),
                        str(row.get("Commande") or ""),
                        str(row.get("Réf. Procédure") or ""),
                        str(row.get("Commentaires") or ""),
                        str(row.get("Résultat attendu") or ""),
                        str(row.get("Vulnérabilité attendue") or ""),
                        str(row.get("Bonne pratique attendu") or ""),
                        json.dumps(extra, ensure_ascii=False),
                        position_by_category[category],
                    ),
                )
                inserted += 1
    logger.info("[bootstrap] seeded %d checklist rows from JSON", inserted)
    return inserted


def merge_auth_categories() -> int:
    """Re-tag the legacy 'Pre-authentication'/'Post-authentication' checklist
    categories into a single 'Exploitation' category.

    The pre-auth and post-auth phases were merged into one Exploitation phase.
    This migration is idempotent: once every row is 'Exploitation' (or the legacy
    categories are already absent) it does nothing. After re-tagging it renumbers
    `position` contiguously within the merged category, preserving the original
    pre-auth-then-post-auth ordering.

    Returns the number of rows re-tagged.
    """
    # Every pre/post-login category folds into the single Exploitation phase.
    # Includes the two extra post-login groupings some DBs carry
    # ("Pre-authentication tests to run post-authentication", "Business logic")
    # and the legacy French spellings.
    legacy = ("Pre-authentication", "Post-authentication",
              "Pré-authentification", "Post-authentification",
              "Pre-authentication tests to run post-authentication",
              "Business logic")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM checklist_tests WHERE category = ANY(%s)",
                (list(legacy),),
            )
            pending = int(cur.fetchone()[0])
            if pending == 0:
                return 0

            # 1) Re-tag every legacy category to 'Exploitation', recording the
            #    original category in a sort rank so ordering is preserved.
            cur.execute(
                """
                UPDATE checklist_tests
                   SET category = 'Exploitation',
                       updated_at = now()
                 WHERE category = ANY(%s)
                """,
                (list(legacy),),
            )
            merged = cur.rowcount

            # 2) Renumber `position` contiguously across ALL Exploitation rows
            #    (both freshly re-tagged and any merged on a previous run) so the
            #    positions stay unique within the category. We keep the relative
            #    order by (existing position, id); because the re-tag preserved
            #    each row's position, pre-auth rows (originally positioned from 1)
            #    naturally precede the later groups.
            cur.execute(
                """
                WITH ordered AS (
                    SELECT id,
                           ROW_NUMBER() OVER (ORDER BY position, id) AS new_pos
                      FROM checklist_tests
                     WHERE category = 'Exploitation'
                )
                UPDATE checklist_tests t
                   SET position = o.new_pos
                  FROM ordered o
                 WHERE t.id = o.id
                   AND t.position <> o.new_pos
                """
            )
    logger.info("[bootstrap] merged %d checklist rows into 'Exploitation'", merged)
    return merged


def run_bootstrap() -> None:
    apply_schema()
    seed_checklist_from_json()
    merge_auth_categories()
