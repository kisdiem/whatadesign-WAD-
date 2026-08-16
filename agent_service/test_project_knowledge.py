from __future__ import annotations

import asyncio
import unittest

from .project_knowledge import knowledge_manifest, search_project_knowledge
from .repository import UnavailableRepository


class ProjectKnowledgeTests(unittest.TestCase):
    def test_chinese_multiscale_query_retrieves_project_method(self) -> None:
        results = search_project_knowledge("为什么要用 1h 24h 7d 30d 多尺度主动检索？", top_k=3, scope=["project"])
        self.assertTrue(results)
        self.assertEqual(results[0]["document_id"], "KB-WAD-INNOV-MULTISCALE")

    def test_scoring_query_retrieves_weak_fusion_rule(self) -> None:
        results = search_project_knowledge("综合风险评分的依据和权重是什么？", top_k=2, scope=["project"])
        self.assertTrue(results)
        self.assertEqual(results[0]["document_id"], "KB-WAD-SCORE-WEAK-FUSION-V2")
        self.assertIn("36%", results[0]["content"])

    def test_project_knowledge_remains_available_without_security_repository(self) -> None:
        result = asyncio.run(
            UnavailableRepository().search_knowledge("真实标签为什么只用于评测", 3, ["project"])
        )
        self.assertTrue(result.ok)
        self.assertIn("KB-WAD-EVAL-PROTOCOL", result.evidence_refs)

    def test_manifest_declares_label_isolation(self) -> None:
        manifest = knowledge_manifest()
        self.assertGreaterEqual(manifest["project_documents"], 8)
        self.assertFalse(manifest["labels_used_for_detection"])


if __name__ == "__main__":
    unittest.main()
