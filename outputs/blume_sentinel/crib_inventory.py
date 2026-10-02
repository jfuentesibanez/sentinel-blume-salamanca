#!/usr/bin/env python3
"""Necessary letter-inventory constraints for literal cribs under pure transposition.

Feasibility is NOT evidence of occurrence. No transliteration is assumed.
"""
from collections import Counter
import json
from pathlib import Path
from verify_sources import normalize

ROOT = Path(__file__).resolve().parent
TERMS = ["HOVAG", "PATVAG", "CEDRIC", "VICTOR", "RUDOLF", "WERNEROSWALD", "OSWALD",
         "WALTHERCETTO", "PAULHOLZACH", "HANSHEUSSER", "HOLZVERZUCKERUNGSAG", "BAHNHOFSTRASSE",
         "KILOS", "PESETAS", "LANA", "SALAMANCA", "BLUME", "ALGODON", "PRECIOS",
         "FRANCO", "SANSEBASTIAN", "IMPORTACION", "EXPORTACION", "COMPENSACION", "ACEITEOLIVA"]
result = []
for term in TERMS:
    row = {"term": term, "messages": {}}
    for name in ("ct1.txt", "ct2.txt"):
        have = Counter(normalize((ROOT / "sources" / name).read_bytes()))
        need = Counter(term)
        missing = {c: n-have[c] for c, n in need.items() if n > have[c]}
        row["messages"][name] = {"feasible_inventory_only": not missing, "missing_multiplicities": missing}
    result.append(row)
print(json.dumps({"assumption": "Literal A-Z preserved by pure transposition. Terms are hypotheses, not recovered words.",
                  "results": result}, ensure_ascii=False, indent=2))
