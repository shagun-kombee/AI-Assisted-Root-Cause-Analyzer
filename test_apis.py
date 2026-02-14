"""
Comprehensive Test Cases for Root Cause Analyzer APIs
Tests all three endpoints: /correlate, /timeline, /rca
Covers both happy cases and negative scenarios
"""

import unittest
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"


class TestCorrelateAPI(unittest.TestCase):
    """Test cases for /correlate endpoint"""
    
    def test_happy_case_valid_request_id(self):
        """Happy Case: Valid request_id with matching logs"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": "Order created successfully"
                },
                {
                    "timestamp": "2026-02-14T10:32:22Z",
                    "level": "INFO",
                    "service": "payment-service",
                    "request_id": "req-123",
                    "event": "payment_started",
                    "message": "Payment initiated"
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["request_id"], "req-123")
        self.assertEqual(data["total_count"], 2)
        self.assertEqual(len(data["correlated_logs"]), 2)
    
    def test_happy_case_extract_from_logs(self):
        """Happy Case: Extract request_id from logs when not provided"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-456",
                    "event": "order_created",
                    "message": "Order created"
                }
            ]
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["request_id"], "req-456")
    
    def test_happy_case_session_id(self):
        """Happy Case: Use session_id for correlation"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "user-service",
                    "session_id": "session-789",
                    "event": "user_login",
                    "message": "User logged in"
                },
                {
                    "timestamp": "2026-02-14T10:32:22Z",
                    "level": "INFO",
                    "service": "user-service",
                    "session_id": "session-789",
                    "event": "session_created",
                    "message": "Session created"
                }
            ],
            "session_id": "session-789"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["request_id"], "session-789")
        self.assertEqual(data["total_count"], 2)
    
    def test_negative_case_empty_request_id(self):
        """Negative Case: Empty request_id and no request_id in logs"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": ""
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("request_id", response.json()["detail"].lower())
    
    def test_negative_case_null_request_id(self):
        """Negative Case: Null request_id and no request_id in logs"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": None
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 400)
    
    def test_negative_case_invalid_timestamp(self):
        """Negative Case: Invalid timestamp format"""
        payload = {
            "logs": [
                {
                    "timestamp": "invalid-date",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_timestamp(self):
        """Negative Case: Empty timestamp"""
        payload = {
            "logs": [
                {
                    "timestamp": "",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_blank_timestamp(self):
        """Negative Case: Blank/whitespace timestamp"""
        payload = {
            "logs": [
                {
                    "timestamp": "   ",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_message(self):
        """Negative Case: Empty message"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": ""
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_service(self):
        """Negative Case: Empty service name"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_invalid_level(self):
        """Negative Case: Invalid log level"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INVALID",
                    "service": "order-service",
                    "request_id": "req-123",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_logs(self):
        """Negative Case: Empty logs array"""
        payload = {
            "logs": [],
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_missing_logs(self):
        """Negative Case: Missing logs field"""
        payload = {
            "request_id": "req-123"
        }
        response = requests.post(f"{BASE_URL}/correlate", json=payload)
        self.assertEqual(response.status_code, 422)


class TestTimelineAPI(unittest.TestCase):
    """Test cases for /timeline endpoint"""
    
    def test_happy_case_ascending_order(self):
        """Happy Case: Timeline sorted ascending (oldest to newest)"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:25Z",
                    "level": "ERROR",
                    "service": "payment-service",
                    "request_id": "req-timeline-1",
                    "event": "payment_failed",
                    "message": "Payment failed"
                },
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-1",
                    "event": "order_created",
                    "message": "Order created"
                },
                {
                    "timestamp": "2026-02-14T10:32:22Z",
                    "level": "INFO",
                    "service": "payment-service",
                    "request_id": "req-timeline-1",
                    "event": "payment_started",
                    "message": "Payment started"
                }
            ],
            "request_id": "req-timeline-1",
            "sort_order": "asc"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["timeline"]), 3)
        # Verify ascending order
        timestamps = [log["timestamp"] for log in data["timeline"]]
        self.assertEqual(timestamps[0], "2026-02-14T10:32:21Z")
        self.assertEqual(timestamps[1], "2026-02-14T10:32:22Z")
        self.assertEqual(timestamps[2], "2026-02-14T10:32:25Z")
    
    def test_happy_case_descending_order(self):
        """Happy Case: Timeline sorted descending (newest to oldest)"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-2",
                    "event": "order_created",
                    "message": "Order created"
                },
                {
                    "timestamp": "2026-02-14T10:32:25Z",
                    "level": "ERROR",
                    "service": "payment-service",
                    "request_id": "req-timeline-2",
                    "event": "payment_failed",
                    "message": "Payment failed"
                }
            ],
            "request_id": "req-timeline-2",
            "sort_order": "desc"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        timestamps = [log["timestamp"] for log in data["timeline"]]
        self.assertEqual(timestamps[0], "2026-02-14T10:32:25Z")
        self.assertEqual(timestamps[1], "2026-02-14T10:32:21Z")
    
    def test_happy_case_duration_calculation(self):
        """Happy Case: Duration is calculated correctly"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-3",
                    "event": "order_created",
                    "message": "Order created"
                },
                {
                    "timestamp": "2026-02-14T10:32:25Z",
                    "level": "INFO",
                    "service": "payment-service",
                    "request_id": "req-timeline-3",
                    "event": "payment_completed",
                    "message": "Payment completed"
                }
            ],
            "request_id": "req-timeline-3",
            "sort_order": "asc"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNotNone(data.get("duration_ms"))
        # 4 seconds = 4000ms
        self.assertGreaterEqual(data["duration_ms"], 3000)
        self.assertLessEqual(data["duration_ms"], 5000)
    
    def test_happy_case_default_sort_order(self):
        """Happy Case: Default sort order is ascending"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:25Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-4",
                    "event": "order_created",
                    "message": "Order created"
                },
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-4",
                    "event": "order_started",
                    "message": "Order started"
                }
            ],
            "request_id": "req-timeline-4"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        timestamps = [log["timestamp"] for log in data["timeline"]]
        # Should be sorted ascending by default
        self.assertEqual(timestamps[0], "2026-02-14T10:32:21Z")
    
    def test_negative_case_invalid_timestamp(self):
        """Negative Case: Invalid timestamp format"""
        payload = {
            "logs": [
                {
                    "timestamp": "not-a-date",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-5",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-timeline-5"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        # Should either reject or skip invalid timestamp
        self.assertIn(response.status_code, [400, 422])
    
    def test_negative_case_blank_timestamp(self):
        """Negative Case: Blank timestamp"""
        payload = {
            "logs": [
                {
                    "timestamp": "   ",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-6",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-timeline-6"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_request_id(self):
        """Negative Case: Empty request_id"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": ""
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 400)
    
    def test_negative_case_invalid_sort_order(self):
        """Negative Case: Invalid sort_order"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-timeline-7",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-timeline-7",
            "sort_order": "invalid"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_no_matching_logs(self):
        """Negative Case: No logs match request_id"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:21Z",
                    "level": "INFO",
                    "service": "order-service",
                    "request_id": "req-other",
                    "event": "order_created",
                    "message": "Order created"
                }
            ],
            "request_id": "req-not-found"
        }
        response = requests.post(f"{BASE_URL}/timeline", json=payload)
        self.assertEqual(response.status_code, 404)


class TestRCAAPI(unittest.TestCase):
    """Test cases for /rca endpoint"""
    
    def test_happy_case_timeout_detection(self):
        """Happy Case: Detects timeout as root cause"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "INFO",
                    "service": "api-gateway",
                    "request_id": "req-rca-1",
                    "event": "request_received",
                    "message": "Payment request received"
                },
                {
                    "timestamp": "2026-02-14T10:32:02Z",
                    "level": "INFO",
                    "service": "payment-service",
                    "request_id": "req-rca-1",
                    "event": "payment_initiated",
                    "message": "Payment processing initiated"
                },
                {
                    "timestamp": "2026-02-14T10:32:13Z",
                    "level": "ERROR",
                    "service": "payment-service",
                    "request_id": "req-rca-1",
                    "event": "gateway_timeout",
                    "message": "Payment gateway timeout after 10 seconds",
                    "error_code": "PG_TIMEOUT"
                }
            ],
            "request_id": "req-rca-1"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["root_causes"]), 0)
        self.assertIsNotNone(data.get("summary"))
    
    def test_happy_case_service_unavailable(self):
        """Happy Case: Detects service unavailability"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "INFO",
                    "service": "api-gateway",
                    "request_id": "req-rca-2",
                    "event": "request_received",
                    "message": "Request received"
                },
                {
                    "timestamp": "2026-02-14T10:32:02Z",
                    "level": "ERROR",
                    "service": "payment-service",
                    "request_id": "req-rca-2",
                    "event": "service_unavailable",
                    "message": "Payment service unavailable",
                    "error_code": "SERVICE_UNAVAILABLE"
                }
            ],
            "request_id": "req-rca-2"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["root_causes"]), 0)
    
    def test_happy_case_validation_error(self):
        """Happy Case: Detects validation errors"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "ERROR",
                    "service": "api-gateway",
                    "request_id": "req-rca-3",
                    "event": "validation_failed",
                    "message": "Invalid request format",
                    "error_code": "VALIDATION_ERROR"
                }
            ],
            "request_id": "req-rca-3"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["root_causes"]), 0)
    
    def test_happy_case_failure_propagation(self):
        """Happy Case: Detects failure propagation"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "INFO",
                    "service": "api-gateway",
                    "request_id": "req-rca-4",
                    "event": "request_received",
                    "message": "Request received"
                },
                {
                    "timestamp": "2026-02-14T10:32:02Z",
                    "level": "ERROR",
                    "service": "payment-service",
                    "request_id": "req-rca-4",
                    "event": "payment_failed",
                    "message": "Payment failed",
                    "error_code": "PAYMENT_FAILED"
                },
                {
                    "timestamp": "2026-02-14T10:32:03Z",
                    "level": "ERROR",
                    "service": "api-gateway",
                    "request_id": "req-rca-4",
                    "event": "request_failed",
                    "message": "Request failed",
                    "error_code": "REQUEST_FAILED"
                }
            ],
            "request_id": "req-rca-4"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Should detect failure propagation
        self.assertGreater(len(data.get("failure_propagation", [])), 0)
    
    def test_negative_case_empty_request_id(self):
        """Negative Case: Empty request_id"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "INFO",
                    "service": "api-gateway",
                    "event": "request_received",
                    "message": "Request received"
                }
            ],
            "request_id": ""
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 400)
    
    def test_negative_case_invalid_timestamp(self):
        """Negative Case: Invalid timestamp"""
        payload = {
            "logs": [
                {
                    "timestamp": "invalid-date",
                    "level": "INFO",
                    "service": "api-gateway",
                    "request_id": "req-rca-5",
                    "event": "request_received",
                    "message": "Request received"
                }
            ],
            "request_id": "req-rca-5"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_message(self):
        """Negative Case: Empty message"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "INFO",
                    "service": "api-gateway",
                    "request_id": "req-rca-6",
                    "event": "request_received",
                    "message": ""
                }
            ],
            "request_id": "req-rca-6"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_invalid_level(self):
        """Negative Case: Invalid log level"""
        payload = {
            "logs": [
                {
                    "timestamp": "2026-02-14T10:32:00Z",
                    "level": "INVALID",
                    "service": "api-gateway",
                    "request_id": "req-rca-7",
                    "event": "request_received",
                    "message": "Request received"
                }
            ],
            "request_id": "req-rca-7"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_negative_case_empty_logs(self):
        """Negative Case: Empty logs array"""
        payload = {
            "logs": [],
            "request_id": "req-rca-8"
        }
        response = requests.post(f"{BASE_URL}/rca", json=payload)
        self.assertEqual(response.status_code, 422)


class TestHealthEndpoint(unittest.TestCase):
    """Test cases for /health endpoint"""
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = requests.get(f"{BASE_URL}/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertEqual(data["status"], "running")
        self.assertIn("apis", data)


if __name__ == "__main__":
    print("=" * 70)
    print("🧪 Running Comprehensive Test Suite for Root Cause Analyzer APIs")
    print("=" * 70)
    print("\n⚠️  Make sure the server is running: python app.py")
    print("=" * 70)
    
    # Run tests
    unittest.main(verbosity=2)

