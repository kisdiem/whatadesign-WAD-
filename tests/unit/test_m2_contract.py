from src.common.schema import EventFrame
from src.entities.m2_resolver import M2EntityResolver


def test_m2_is_deterministic_and_type_aware():
    frame = EventFrame("r", entities=["10.0.0.1", r"C:\Temp\Drop.exe", "CORP\\alice"])
    first = M2EntityResolver().resolve(frame)
    second = M2EntityResolver().resolve(frame)
    assert [(x.entity_id, x.entity_type) for x in first] == [(x.entity_id, x.entity_type) for x in second]
    assert [x.entity_type for x in first] == ["ip", "path", "account"]


def test_m2_alias_hook_does_not_change_entity_type():
    class Provider:
        def resolve_alias(self, value, entity_type):
            return "canonical-host" if entity_type == "token" else None

    frame = EventFrame("r", entities=["Host-A"])
    result = M2EntityResolver(Provider()).resolve(frame)[0]
    assert result.canonical_value == "canonical-host"
    assert result.entity_type == "token"
