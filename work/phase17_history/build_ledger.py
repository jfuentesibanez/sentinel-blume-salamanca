import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def record(path):
    payload = path.read_bytes()
    return {"path": path.name, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}

plan = json.loads((ROOT / "plan.json").read_text())
responses = []
for filename, query_numbers in [("web_query1.json", [1]), ("web_queries2_3.json", [2, 3])]:
    path = ROOT / filename
    response = json.loads(path.read_text())
    urls = list(dict.fromkeys(re.findall(r"\((https?://[^)\s]+)\)", response)))
    responses.append({
        "query_numbers": query_numbers,
        "raw_response": record(path),
        "source_urls": urls,
        "distinct_source_urls": len(urls),
        "gazeta_source_urls": [url for url in urls if "/gazeta/" in url],
        "gazeta_target_period_urls": [url for url in urls if re.search(r"/gazeta/dias/193[678]/", url)],
        "result_limit": "Results are a search-engine response, not a direct query of the BOE historical database. The second response combines two query texts, so URLs are not attributed to one of those two queries individually."
    })

ledger = {
    "phase": "17-history",
    "status": "closed_bounded_negative",
    "recorded_at_utc": "2026-10-03T01:14:58Z",
    "plan": record(ROOT / "plan.json"),
    "queries": [{"n": i + 1, "query": query, "domains": ["boe.es"]} for i, query in enumerate(plan["queries_in_order"])],
    "request_calls": 2,
    "query_texts": 3,
    "document_open_calls": 0,
    "responses": responses,
    "interpretation": "No identifying reference from 1936–1938 was observed in these returned results. The search engine returned BOE/BORME pages outside the requested historical path; the sole Gazeta URL belongs to 1856. No page, original document, scan or registry was opened.",
    "negative_scope": "This is a failed bounded web-index route, not a negative search of the complete official corpus. Neither full-text coverage nor enforcement of the path filter was verified. The dates 1936/1937 can occur as unrelated numbers or retrospective references in modern pages.",
    "identity": "No BLUME candidate identified. No modern names or companies are attributed to the 1937 recipient.",
    "costs": {"IDP": 0, "solver_runs": 0, "contacts": 0, "orders": 0, "purchases": 0, "account_changes": 0, "UI_calls": 0},
    "closure": "No further requests, syntax changes or retries in this round. A later route needs genuinely new primary evidence or a separately planned direct official-database search.",
    "publication": "Raw response JSON strings contain externally supplied search excerpts and remain local/reference-only. This script, plan, ledger and own result note are eligible for review and publication."
}
(ROOT / "ledger.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"query_texts": 3, "web_request_calls": 2, "opens": 0, "response_url_counts": [r["distinct_source_urls"] for r in responses], "gazeta_target_period_urls": sum(len(r["gazeta_target_period_urls"]) for r in responses), "IDP": 0}))
