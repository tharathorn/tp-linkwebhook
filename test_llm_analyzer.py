import unittest

from llm_analyzer import extract_json_block, normalize_analysis, should_send_alert


class LlmAnalyzerTest(unittest.TestCase):
    def test_extract_json_block_from_fenced_text(self):
        block = extract_json_block("```json\n{\"priority\":\"high\"}\n```")
        self.assertEqual(block, "{\"priority\":\"high\"}")

    def test_normalize_analysis_clamps_values(self):
        normalized = normalize_analysis({"priority": "BAD", "score": 5, "recommended_actions": "a"})
        self.assertEqual(normalized["priority"], "medium")
        self.assertEqual(normalized["score"], 1.0)
        self.assertEqual(normalized["recommended_actions"], ["a"])

    def test_should_send_alert_with_threshold(self):
        self.assertTrue(should_send_alert({"score": 0.9, "priority": "low", "requires_human": False}, 0.75))
        self.assertFalse(should_send_alert({"score": 0.2, "priority": "low", "requires_human": False}, 0.75))


if __name__ == "__main__":
    unittest.main()
