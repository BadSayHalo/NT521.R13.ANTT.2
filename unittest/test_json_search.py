import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):
    '''test module to search function test in recursive_json_search.py'''
    
    # FUNCTIONAL TESTS
    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        # Tìm một key hợp lệ ("issueSummary") bằng một role hợp lệ ("viewer").
        self.assertTrue([] != json_search("issueSummary", data, role="viewer"))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        # Tìm kiếm một key không tồn tại trong data gốc.
        self.assertTrue([] == json_search("nonExistentKey999", data, role="viewer"))

    def test_is_a_list(self):
        '''Should return a list'''
        # hàm json_search luôn luôn phải trả về  list format.
        self.assertIsInstance(json_search("issueSummary", data, role="viewer"), list)

    # SECURITY TESTS
    def test_stride_information_disclosure(self):
        '''Prevent Information Disclosure: Viewer is not allowed to read apiKey'''
        # Xác minh rằng RBAC hoạt động đúng, chặn role "viewer" đọc key nhạy cảm "apiKey".
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_stride_elevation_of_privilege(self):
        '''Prevent Elevation of Privilege: Block access to apiKey if role is viewer or None'''
        # Chống leo thang đặc quyền (Elevation of Privilege): 
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)
        result = json_search("apiKey", data, role=None)
        self.assertEqual([], result)

    def test_stride_spoofing(self):
        '''Prevent Spoofing: Block access when using an invalid/fake role'''
        # Chống giả mạo: Truyền vào một role rác không có thật trong hệ thống
        result = json_search("apiKey", data, role="hacker")
        self.assertEqual([], result)

    def test_stride_denial_of_service(self):
        '''Prevent DoS: Catch RecursionError when JSON structure is nested too deeply'''
        # Chống tấn công Dos: 
        deep_json = {"key": "value"}
        for _ in range(2000):
            deep_json = {"nested": deep_json}
        
        with self.assertRaises(RecursionError):
            json_search("key", deep_json, role="admin")

if __name__ == '__main__':
    unittest.main()