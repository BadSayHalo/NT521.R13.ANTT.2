"""Unit tests for recursive_json_search.json_search."""

import unittest

from recursive_json_search import json_search
from test_data import data, key1, key2


class json_search_test(unittest.TestCase):
    def test_search_found(self):
        """An allowed role receives a matching item found deep in a dict/list tree."""
        expected = [{key1: "Network Device 10.10.20.82 Is Unreachable From Controller"}]
        self.assertEqual(json_search(key1, data, role="viewer"), expected)

    def test_search_not_found(self):
        """A search for a missing key returns an empty list."""
        self.assertEqual(json_search(key2, data, role="viewer"), [])

    def test_is_a_list(self):
        """The search result is a list even when no matching fields exist."""
        result = json_search(key2, data, role="viewer")
        self.assertIsInstance(result, list)

    def test_api_key_denied_to_operator(self):
        """Operators cannot read apiKey because policy reserves it for admins."""
        self.assertEqual(json_search("apiKey", data, role="operator"), [])

    def test_management_ip_denied_to_viewer(self):
        """Viewers cannot read managementIpAddress under the field-level policy."""
        self.assertEqual(json_search("managementIpAddress", data, role="viewer"), [])

    def test_protected_field_denied_without_role(self):
        """An unauthenticated caller receives no value for a protected field."""
        self.assertEqual(json_search("issueSummary", data), [])

    def test_api_key_allowed_to_admin(self):
        """Administrators receive apiKey when policy explicitly grants access."""
        self.assertEqual(
            json_search("apiKey", data, role="admin"),
            [{"apiKey": "SNMP-COMMUNITY-STRING-7f3a9c"}],
        )


if __name__ == "__main__":
    unittest.main()
