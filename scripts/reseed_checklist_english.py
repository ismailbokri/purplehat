"""Re-seed the live `checklist_tests` table from the (now English) checklist JSON.

Why this exists
---------------
`db/bootstrap.py` seeds `checklist_tests` from palnner/checklist.json ONLY when
the table is empty (first startup). On an already-running instance the table is
populated, so simply translating the JSON does not change what the app shows.
This script pushes the English content of the JSON onto the existing rows.

What it does
------------
For every test in the JSON's "Pentest Web" blocks, it UPDATEs the matching row
(matched on `test_id`) with the translated text columns:
    tests, outils, commande, ref_procedure, commentaires,
    resultat_attendu, vulnerabilite_attendue, bonne_pratique_attendu, extra

It does NOT touch: id, test_id, category, position — so ordering, category
grouping (which the backend matches on in French), and any foreign keys are
preserved. Rows present in the DB but absent from the JSON are left untouched
and reported. Missing rows (in JSON, not in DB) are reported, not inserted,
so this stays a translation refresh rather than a re-import.

Usage
-----
    python scripts/reseed_checklist_english.py            # apply updates
    python scripts/reseed_checklist_english.py --dry-run  # show what would change

Idempotent: running it twice is a no-op the second time.
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

JSON_PATH = ROOT / "palnner" / "checklist.json"

# Same column/extra split bootstrap.py uses, so `extra` stays consistent.
_COLUMN_FIELDS = {
    "ID", "Catégorie", "Tests", "Outils", "Commande", "Réf. Procédure",
    "Commentaires", "Résultat attendu", "Vulnérabilité attendue",
    "Bonne pratique attendu",
}


def _json_rows():
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    for block in data.get("Pentest Web", []):
        category = block.get("category", "")
        for test in block.get("tests", []):
            row = dict(test)
            row.setdefault("Catégorie", category)
            yield row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="report changes without writing to the DB")
    args = ap.parse_args()

    from db.connection import get_conn  # imported here so --help works without DB env

    rows = list(_json_rows())

    updated, unchanged, missing = 0, 0, []

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Map existing DB rows by test_id.
            cur.execute("SELECT test_id FROM checklist_tests")
            existing = {str(r[0]) for r in cur.fetchall()}

            for row in rows:
                tid = str(row.get("ID") or "")
                if tid not in existing:
                    missing.append(tid)
                    continue

                extra = {k: v for k, v in row.items() if k not in _COLUMN_FIELDS}
                params = (
                    str(row.get("Tests") or ""),
                    str(row.get("Outils") or ""),
                    str(row.get("Commande") or ""),
                    str(row.get("Réf. Procédure") or ""),
                    str(row.get("Commentaires") or ""),
                    str(row.get("Résultat attendu") or ""),
                    str(row.get("Vulnérabilité attendue") or ""),
                    str(row.get("Bonne pratique attendu") or ""),
                    json.dumps(extra, ensure_ascii=False),
                    tid,
                )

                if args.dry_run:
                    updated += 1
                    continue

                cur.execute(
                    """
                    UPDATE checklist_tests SET
                        tests                  = %s,
                        outils                 = %s,
                        commande               = %s,
                        ref_procedure          = %s,
                        commentaires           = %s,
                        resultat_attendu       = %s,
                        vulnerabilite_attendue = %s,
                        bonne_pratique_attendu = %s,
                        extra                  = %s::jsonb
                    WHERE test_id = %s
                    """,
                    params,
                )
                updated += cur.rowcount or 0

    verb = "would update" if args.dry_run else "updated"
    print(f"{verb} {updated} row(s); {len(rows)} test(s) in JSON.")
    if missing:
        print(f"[!] {len(missing)} test(s) in JSON have no matching DB row "
              f"(not inserted): {', '.join(missing)}")
    if not args.dry_run:
        print("Done. The app now serves the English checklist text.")


if __name__ == "__main__":
    main()
