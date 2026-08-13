from pathlib import Path

from src.common.schema import RawRecord, stable_record_id
from src.parsers.m0_drain import M0DrainParser


def test_record_id_is_stable():
    assert stable_record_id("d", "f.log", 3) == stable_record_id("d", "f.log", 3)
    assert stable_record_id("d", "f.log", 3) != stable_record_id("d", "f.log", 4)


def test_template_reuse_and_separation():
    parser = M0DrainParser()
    first = parser.parse(RawRecord("d", "f.log", 1, None, "failed login from 10.0.0.1", parser.VERSION))
    second = parser.parse(RawRecord("d", "f.log", 2, None, "failed login from 10.0.0.2", parser.VERSION))
    third = parser.parse(RawRecord("d", "f.log", 3, None, "successful login from 10.0.0.2", parser.VERSION))
    assert first.template_id == second.template_id
    assert third.template_id != first.template_id


def test_parse_lines_skips_empty_lines(tmp_path: Path):
    path = tmp_path / "sample.log"
    path.write_text("a\n\n b\n", encoding="utf-8")
    rows = list(M0DrainParser().parse_lines("d", path))
    assert len(rows) == 2


def test_safe_mask_preserves_security_constants():
    masked = M0DrainParser.safe_mask("EventID=4624 status=Success from 10.0.0.1 id=123")
    assert "EventID=4624" in masked
    assert "status=Success" in masked
    assert "<IP>" in masked
    assert "id=<NUM>" in masked


def test_template_fingerprint_and_cache_round_trip(tmp_path: Path):
    parser = M0DrainParser()
    parsed = parser.parse(RawRecord("d", "f.log", 1, None, "login from 10.0.0.1", parser.VERSION))
    assert parsed.fields["template_fingerprint"] == M0DrainParser.template_fingerprint(parsed.fields["template"])
    path = tmp_path / "cache.json"
    parser.save_cache(path)
    loaded = M0DrainParser.load_cache(path)
    assert loaded["templates"] == parser.catalog()["templates"]
