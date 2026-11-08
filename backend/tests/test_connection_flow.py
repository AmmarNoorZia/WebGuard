"""Offline contract tests for WebGuard's Flask -> Supabase authentication and target flow.
Run: python -m unittest discover -s tests -v
"""
import unittest
import uuid
from unittest.mock import patch

import app as webguard

USER_ID = "bc1f8079-49c3-4081-9a8e-2511e80c1a64"
TARGET_ID = "54d36993-9b22-40c3-bd88-872cf67918a2"

class FakeResponse:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data if data is not None else {}
        self.content = b"{}"
    def json(self):
        return self._data

class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.client = webguard.app.test_client()
        self.configuration = patch.multiple(webguard, CONFIGURED=True, SUPABASE_URL="https://unit-test.supabase.co", SUPABASE_KEY="sb_publishable_test")
        self.configuration.start()
        self.addCleanup(self.configuration.stop)

    def bearer(self):
        return {"Authorization": "Bearer fake-test-jwt"}

    def test_health_reports_backend_ready_but_scanner_not_ready(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json["supabase_configured"])
        self.assertFalse(r.json["scanner_ready"])

    def test_me_rejects_missing_token(self):
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)

    @patch.object(webguard.requests, "get")
    def test_me_accepts_supabase_verified_user(self, mock_get):
        mock_get.return_value = FakeResponse(data={"id": USER_ID, "email": "test@example.com"})
        r = self.client.get("/api/me", headers=self.bearer())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["id"], USER_ID)
        args, kwargs = mock_get.call_args
        self.assertIn("/auth/v1/user", args[0])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer fake-test-jwt")

    @patch.object(webguard.requests, "get")
    def test_me_rejects_invalid_token(self, mock_get):
        mock_get.return_value = FakeResponse(status=401)
        self.assertEqual(self.client.get("/api/me", headers=self.bearer()).status_code, 401)

    @patch.object(webguard.requests, "request")
    @patch.object(webguard.requests, "get")
    def test_create_target_sets_authenticated_user_and_records_activity(self, mock_get, mock_request):
        mock_get.return_value = FakeResponse(data={"id": USER_ID})
        created = {"id": TARGET_ID, "user_id": USER_ID, "name": "Local Test A", "url": "http://localhost:5001", "environment": "Local test"}
        mock_request.side_effect = [FakeResponse(status=201, data=[created]), FakeResponse(status=201, data=[])]
        r = self.client.post("/api/targets", headers=self.bearer(), json={"name": "Local Test A", "url": "http://localhost:5001", "environment": "Local test"})
        self.assertEqual(r.status_code, 201, r.json)
        self.assertEqual(r.json["target"]["id"], TARGET_ID)
        _, kwargs = mock_request.call_args_list[0]
        self.assertEqual(kwargs["json"]["user_id"], USER_ID)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer fake-test-jwt")
        self.assertEqual(mock_request.call_count, 2)

    @patch.object(webguard.requests, "request")
    @patch.object(webguard.requests, "get")
    def test_list_targets_uses_user_filter(self, mock_get, mock_request):
        mock_get.return_value = FakeResponse(data={"id": USER_ID})
        mock_request.return_value = FakeResponse(data=[{"id": TARGET_ID, "name": "A"}])
        r = self.client.get("/api/targets", headers=self.bearer())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["targets"][0]["name"], "A")
        self.assertEqual(mock_request.call_args.kwargs["params"]["user_id"], f"eq.{USER_ID}")

    @patch.object(webguard.requests, "get")
    def test_create_rejects_external_websites_before_database(self, mock_get):
        mock_get.return_value = FakeResponse(data={"id": USER_ID})
        r = self.client.post("/api/targets", headers=self.bearer(), json={"name": "Unsafe", "url": "https://example.com"})
        self.assertEqual(r.status_code, 400)

    @patch.object(webguard.requests, "request")
    @patch.object(webguard.requests, "get")
    def test_delete_target(self, mock_get, mock_request):
        mock_get.return_value = FakeResponse(data={"id": USER_ID})
        mock_request.side_effect = [FakeResponse(data=[{"id": TARGET_ID, "name": "A"}]), FakeResponse(data=[]), FakeResponse(data=[])]
        r = self.client.delete(f"/api/targets/{TARGET_ID}", headers=self.bearer())
        self.assertEqual(r.status_code, 200, r.json)
        self.assertTrue(r.json["deleted"])
        self.assertEqual(mock_request.call_args_list[1].kwargs["params"]["user_id"], f"eq.{USER_ID}")

    @patch.object(webguard.requests, "get")
    def test_delete_rejects_invalid_uuid(self, mock_get):
        mock_get.return_value = FakeResponse(data={"id": USER_ID})
        self.assertEqual(self.client.delete("/api/targets/not-a-uuid", headers=self.bearer()).status_code, 400)

if __name__ == "__main__":
    unittest.main()
