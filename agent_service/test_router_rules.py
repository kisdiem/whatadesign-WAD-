from __future__ import annotations

import asyncio
import unittest

from .models import AgentQueryRequest, AgentRequestContext
from .repository import UnavailableRepository
from .runtime import AgentRuntime


class RouterRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = AgentRuntime(UnavailableRepository())

    def resolve(self, message: str, *, mode: str = "auto", context: AgentRequestContext | None = None):
        request = AgentQueryRequest(
            conversation_id="TEST-CONV",
            mode=mode,
            message=message,
            context=context or AgentRequestContext(),
        )
        return asyncio.run(self.runtime.resolve_mode(request))

    def test_user_selected_mode_is_never_overridden(self) -> None:
        decision = self.resolve("HOST-18 最近有什么异常？", mode="general")
        self.assertEqual(decision.mode, "general")
        self.assertEqual(decision.reason_code, "USER_SELECTED")

    def test_bound_security_context_forces_security_in_auto(self) -> None:
        decision = self.resolve(
            "总结一下",
            context=AgentRequestContext(finding_ids=["WIN-20260809-1422"]),
        )
        self.assertEqual(decision.mode, "security")

    def test_specific_environment_query_is_security(self) -> None:
        decision = self.resolve("HOST-18 最近有什么异常？")
        self.assertEqual(decision.mode, "security")

    def test_log_definition_is_knowledge_not_security(self) -> None:
        decision = self.resolve("什么是日志？")
        self.assertEqual(decision.mode, "knowledge")

    def test_host_definition_is_knowledge_not_security(self) -> None:
        decision = self.resolve("主机是什么意思？")
        self.assertEqual(decision.mode, "knowledge")

    def test_attack_technique_definition_is_knowledge(self) -> None:
        decision = self.resolve("MITRE ATT&CK 的 T1021 是什么意思？")
        self.assertEqual(decision.mode, "knowledge")


if __name__ == "__main__":
    unittest.main()
