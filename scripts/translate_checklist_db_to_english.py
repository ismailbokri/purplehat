# -*- coding: utf-8 -*-
"""One-time migration: translate the live `checklist_tests` table to English.

Why this exists
---------------
The checklist JSON was translated to English, but the live database was seeded
from the original French export and never refreshed. `db/bootstrap.py` only
seeds when the table is empty, so the app keeps serving the French rows. The
earlier `reseed_checklist_english.py` pushed English *text* onto JSON-matched
rows but deliberately left `category` in French and never touched the ~21 rows
that are in the DB but absent from the JSON (Business logic, the "pré-auth à
faire en post-auth" block, and a stray #1255).

This script finishes the job, once and for all:

  1. Backs up every current row to a timestamped JSON file (scripts/backups/).
  2. Pushes the English JSON content onto the 106 JSON-matched rows (text
     columns + English `extra` placeholders).
  3. Writes hand-translated English for the rows that are NOT in the JSON.
  4. Maps every French `category` identifier to its English equivalent.

It is idempotent: a second run changes nothing. Category remapping is applied
last and matches on the known French identifiers, so re-running on an already
English table is a no-op.

Usage
-----
    python scripts/translate_checklist_db_to_english.py            # apply
    python scripts/translate_checklist_db_to_english.py --dry-run  # preview
"""
import argparse
import datetime as _dt
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

JSON_PATH = ROOT / "palnner" / "checklist.json"
BACKUP_DIR = ROOT / "scripts" / "backups"

# Columns that hold display text (everything a tester reads).
_TEXT_COLUMNS = [
    "tests", "outils", "commande", "ref_procedure", "commentaires",
    "resultat_attendu", "vulnerabilite_attendue", "bonne_pratique_attendu",
]

# JSON display keys ↔ DB columns.
_JSON_TO_COLUMN = {
    "Tests": "tests",
    "Outils": "outils",
    "Commande": "commande",
    "Réf. Procédure": "ref_procedure",
    "Commentaires": "commentaires",
    "Résultat attendu": "resultat_attendu",
    "Vulnérabilité attendue": "vulnerabilite_attendue",
    "Bonne pratique attendu": "bonne_pratique_attendu",
}

# Keys that live in dedicated columns; the rest of a JSON row goes to `extra`.
_COLUMN_FIELDS = {
    "ID", "Catégorie", "Tests", "Outils", "Commande", "Réf. Procédure",
    "Commentaires", "Résultat attendu", "Vulnérabilité attendue",
    "Bonne pratique attendu",
}

# French category identifiers → English. Applied to the `category` column.
_CATEGORY_MAP = {
    "Découverte": "Discovery",
    "Pré-authentification": "Pre-authentication",
    "Post-authentification": "Post-authentication",
    "Tests pré-authentification à faire en post-authentification":
        "Pre-authentication tests to run post-authentication",
    "Business logic": "Business logic",  # already English
}

# English consultant-fill placeholders (the `extra` JSONB values), matching the
# English JSON so every row is consistent.
_EXTRA_EN = {
    "Résultat effectif": "To be completed by the consultant during the engagement",
    "Vulnérabilité effective": "To be completed by the consultant during the engagement",
    "Elément impactés": "To be completed by the consultant during the engagement",
    "Bonne pratique effective": "To be completed by the consultant during the engagement",
    "Commentaire consultant": "To be completed by the consultant if the project lead left a comment",
    "Commentaire Chef de projet": "To be completed by the project lead",
    "Proposition d'amélioration": "To be completed by the consultant with any improvement suggestions for this test",
}

# Hand-translated English for the rows present in the DB but NOT in the JSON.
# Keyed by test_id. Only non-empty text columns are overwritten; omitted columns
# are left as-is. The "pré-auth à faire en post-auth" rows (#108–117) hold only
# broken spreadsheet formula references (=C15, =I19 …) with no real content, so
# they get no text rewrite — only the category and `extra` are translated.
_MANUAL_EN = {
    "118": {
        "tests": "Try to manipulate the product identifier, price or quantity value in any action (add, modify, delete, place, pay, …)",
        "outils": "Burp Suite",
        "resultat_attendu": "Parameters controlled / No control",
        "vulnerabilite_attendue": "No validation of sensitive parameters",
    },
    "119": {
        "tests": "Try parameter pollution to use the same coupon twice in the same request",
        "resultat_attendu": "Coupon reuse possible / Not possible",
        "vulnerabilite_attendue": "No limit on how many times a coupon can be used",
    },
    "120": {
        "tests": "Test the multi-stage purchase flow",
        "resultat_attendu": "Flow vulnerable / Not vulnerable",
    },
    "121": {
        "tests": "Try to reuse the same coupon several times",
        "resultat_attendu": "Coupon reuse possible / Not possible",
    },
    "122": {
        "tests": "Check whether coupons are predictable",
        "resultat_attendu": "Coupons predictable / Not predictable",
    },
    "123": {
        "tests": "Check the transaction logic",
        "resultat_attendu": "Transaction logic vulnerable / Not vulnerable",
    },
    "124": {
        "tests": "Change sensitive POST requests to GET",
        "resultat_attendu": "Sending as GET possible / Not possible",
    },
    "125": {
        "tests": "Test IDOR on other users' sensitive data",
        "resultat_attendu": "Sensitive / Not sensitive",
    },
    "126": {
        "tests": "Check PDF generation for IDOR",
        "resultat_attendu": "Sensitive / Not sensitive",
    },
    "127": {
        "tests": "Test a race-condition attack on the payment",
        "outils": "race-the-web",
        "resultat_attendu": "Sensitive / Not sensitive",
    },
    "1255": {
        "tests": "Identify the web technologies in use",
        "outils": "WhatWeb",
        "commande": "whatweb https://target.com",
        "ref_procedure": "WhatWeb — web technology identification",
        "commentaires": "To be completed by the consultant if the project lead left a comment",
        "resultat_attendu": "Web technologies identified without excessive disclosure of sensitive information",
        "vulnerabilite_attendue": "Disclosure of web technology versions that could help identify vulnerabilities",
        "bonne_pratique_attendu": "Masking or limiting fingerprinting information for technologies and versions",
    },
}


def _json_rows():
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    for block in data.get("Pentest Web", []):
        for test in block.get("tests", []):
            yield test


def _english_extra():
    """The English `extra` placeholder block, as stored JSONB."""
    return dict(_EXTRA_EN)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change without writing")
    args = ap.parse_args()

    from db.connection import get_conn  # deferred so --help works without DB env

    json_by_id = {str(t.get("ID")): t for t in _json_rows()}

    text_updates = 0
    extra_updates = 0
    category_updates = 0
    untouched = []

    with get_conn() as conn:
        with conn.cursor() as cur:
            # ── 0. Back up every current row first ────────────────────────────
            cur.execute(
                "SELECT id, test_id, category, " + ", ".join(_TEXT_COLUMNS) +
                ", extra FROM checklist_tests ORDER BY id"
            )
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]

            if not args.dry_run:
                BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                backup = BACKUP_DIR / f"checklist_tests_backup_{stamp}.json"
                backup.write_text(
                    json.dumps(rows, ensure_ascii=False, indent=1, default=str),
                    encoding="utf-8",
                )
                print(f"Backed up {len(rows)} row(s) → {backup}")

            # ── 1. Per-row text + extra updates ───────────────────────────────
            for row in rows:
                tid = str(row["test_id"])
                new_text = {}

                if tid in json_by_id:
                    jr = json_by_id[tid]
                    for jkey, col in _JSON_TO_COLUMN.items():
                        val = jr.get(jkey)
                        new_text[col] = ("" if val is None else str(val))
                    extra = {k: v for k, v in jr.items() if k not in _COLUMN_FIELDS}
                    # Normalise placeholders to the English block.
                    extra = {**_english_extra(), **{k: v for k, v in extra.items()
                                                     if k not in _EXTRA_EN}}
                elif tid in _MANUAL_EN:
                    new_text = dict(_MANUAL_EN[tid])
                    extra = _english_extra()
                else:
                    # Formula-junk rows (#108–117): no real text, only translate
                    # the consultant-fill placeholders.
                    extra = _english_extra()

                # Apply text columns that actually differ.
                set_cols = []
                params = []
                for col in _TEXT_COLUMNS:
                    if col in new_text and (row.get(col) or "") != new_text[col]:
                        set_cols.append(f"{col} = %s")
                        params.append(new_text[col])
                if set_cols:
                    text_updates += 1
                    if not args.dry_run:
                        cur.execute(
                            f"UPDATE checklist_tests SET {', '.join(set_cols)} WHERE id = %s",
                            (*params, row["id"]),
                        )

                # Apply the English extra block if it changed.
                cur_extra = row.get("extra") or {}
                if isinstance(cur_extra, str):
                    try:
                        cur_extra = json.loads(cur_extra)
                    except Exception:
                        cur_extra = {}
                if cur_extra != extra:
                    extra_updates += 1
                    if not args.dry_run:
                        cur.execute(
                            "UPDATE checklist_tests SET extra = %s::jsonb WHERE id = %s",
                            (json.dumps(extra, ensure_ascii=False), row["id"]),
                        )

                if tid not in json_by_id and tid not in _MANUAL_EN:
                    untouched.append(tid)

            # ── 2. Category remapping (last) ──────────────────────────────────
            for fr, en in _CATEGORY_MAP.items():
                if fr == en:
                    continue
                cur.execute(
                    "SELECT COUNT(*) FROM checklist_tests WHERE category = %s", (fr,)
                )
                n = cur.fetchone()[0]
                if n:
                    category_updates += n
                    if not args.dry_run:
                        cur.execute(
                            "UPDATE checklist_tests SET category = %s WHERE category = %s",
                            (en, fr),
                        )

    verb = "would update" if args.dry_run else "updated"
    print(f"{verb}: {text_updates} row(s) text, {extra_updates} row(s) extra, "
          f"{category_updates} row(s) category.")
    if untouched:
        print(f"[i] {len(untouched)} formula-only row(s) had no translatable text "
              f"(category/extra translated): {', '.join(untouched)}")
    if not args.dry_run:
        print("Done. The app now serves the English checklist.")


if __name__ == "__main__":
    main()
