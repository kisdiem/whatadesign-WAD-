from __future__ import annotations

import hashlib
import json
from typing import Any
from src.common.schema import RawRecord, SyntaxParse, stable_record_id


class M0Parser:
    parser_version = "m0-strict-1"

    def parse(self, raw: RawRecord) -> SyntaxParse:
        record_id = raw.raw_record_id or stable_record_id(raw.dataset_id, raw.source_file, raw.source_line)
        ref = f"{raw.source_file}:{raw.source_line}"
        payload = raw.raw_payload
        if isinstance(payload, dict):
            fields = dict(payload)
            template_text = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        else:
            template_text = str(payload)
            fields = {"message": template_text}
        template_id = hashlib.sha256(template_text.encode()).hexdigest()[:16]
        reason = None
        if raw.raw_timestamp is None:
            reason = "missing_timestamp"
        elif not template_text.strip():
            reason = "empty_payload"
        return SyntaxParse(
            dataset_id=raw.dataset_id, record_id=record_id, timestamp=raw.raw_timestamp,
            template_id=template_id, template_text=template_text,
            dynamic_fields=fields, parse_confidence=0.0 if reason else 1.0,
            source_record_ref=ref, parser_version=self.parser_version,
            quarantined=reason is not None, quarantine_reason=reason,
            source_file=raw.source_file, source_line=raw.source_line,
            format="json" if isinstance(payload, dict) else "text", fields=fields,
            raw_record_ref=record_id,
        )
