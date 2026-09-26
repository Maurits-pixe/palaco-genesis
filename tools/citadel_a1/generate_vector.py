"""Explicit fixture regeneration, never part of verification or routine test runs."""
import json
from pathlib import Path
from verify import canonical, digest, without

target = Path(__file__).resolve().parents[2] / "verification" / "citadel-a1"
if any((target / name).exists() for name in ("bundle.json", "expected.json")):
    raise SystemExit("Frozen A1 vectors must never be overwritten. Author a new versioned profile/vector instead.")
target.mkdir(parents=True, exist_ok=True)
manifest = dict(schema_version="0.1", citadel_id="EVA-LA-001", world_id="WORLD-EVA-001", purpose="Long-Term Constitutional Memory", edition="Foundation / canonical baseline", presentation=["Foundation", "Black Edition"], lifecycle="DRAFT", canonical_encoding="PALACO-JSON-A1", cryptographic_profile="SHA256-DOMAIN-A1")
manifest["manifest_digest"] = digest("MANIFEST", manifest)
records = []
for index, (kind, payload, epistemic, evidence) in enumerate([
    ("QuestionRecord", {"question": "Kan EVA deze waarneming onderbouwen?", "language": "nl"}, "UNKNOWN", []),
    ("EvidenceObject", {"observation": "Café — 水 — 🏰\nLine 2", "sample_count": 3, "independent_verification": False}, "UNKNOWN", []),
    ("EpistemicAssessment", {"assessment": "Fixture only; no authority", "confidence_label": "insufficient"}, "INSUFFICIENT", ["eva-la-001:record:2"]),
], 1):
    r = dict(record_id=f"eva-la-001:record:{index}", record_type=kind, schema_version="0.1", citadel_id="EVA-LA-001", world_id="WORLD-EVA-001", sequence=index, previous_digest=records[-1]["record_digest"] if records else None, payload_digest=digest("PAYLOAD", payload), provenance_refs=[records[-1]["record_id"]] if records else [], evidence_refs=evidence, authorization_ref=None, epistemic_state=epistemic, created_at_display="2026-09-26T09:00:00Z", trusted_time_evidence=None, actor_ref="actor:fixture-unverified", signature=None, manifest_digest=manifest["manifest_digest"], payload=payload)
    r["record_digest"] = digest("RECORD", r)
    records.append(r)
bundle = {"manifest": manifest, "records": records}
expected = dict(manifest_digest=manifest["manifest_digest"], head_digest=records[-1]["record_digest"], result="VALID", scope="A1_ENVELOPE_INTEGRITY", payload_canonical_utf8=[canonical(r["payload"]).decode("utf-8") for r in records], payload_digests=[r["payload_digest"] for r in records], record_digests=[r["record_digest"] for r in records])
for name, value in (("bundle.json", bundle), ("expected.json", expected)):
    with (target / name).open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({k:expected[k] for k in ("manifest_digest", "head_digest")}))
