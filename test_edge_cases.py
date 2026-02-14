"""
Test script to verify error handling for edge cases
Run this to test all negative scenarios
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_empty_request_id():
    """Test with empty request_id"""
    print("\n🧪 Test 1: Empty request_id")
    payload = {
        "logs": [
            {
                "timestamp": "2026-02-14T10:32:21Z",
                "level": "INFO",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_started",
                "message": "User login request"
            }
        ],
        "request_id": ""
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 200, "Should extract request_id from logs"

def test_null_request_id():
    """Test with null request_id"""
    print("\n🧪 Test 2: Null request_id")
    payload = {
        "logs": [
            {
                "timestamp": "2026-02-14T10:32:21Z",
                "level": "INFO",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_started",
                "message": "User login request"
            }
        ],
        "request_id": None
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 200, "Should extract request_id from logs"

def test_invalid_timestamp():
    """Test with invalid timestamp"""
    print("\n🧪 Test 3: Invalid timestamp")
    payload = {
        "logs": [
            {
                "timestamp": "invalid-date",
                "level": "INFO",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_started",
                "message": "User login request"
            }
        ],
        "request_id": "req-123"
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 422, "Should reject invalid timestamp"

def test_blank_timestamp():
    """Test with blank timestamp"""
    print("\n🧪 Test 4: Blank timestamp")
    payload = {
        "logs": [
            {
                "timestamp": "   ",
                "level": "INFO",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_started",
                "message": "User login request"
            }
        ],
        "request_id": "req-123"
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 422, "Should reject blank timestamp"

def test_empty_logs():
    """Test with empty logs array"""
    print("\n🧪 Test 5: Empty logs array")
    payload = {
        "logs": [],
        "request_id": "req-123"
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 422, "Should reject empty logs"

def test_no_request_id_anywhere():
    """Test with no request_id in request or logs"""
    print("\n🧪 Test 6: No request_id anywhere")
    payload = {
        "logs": [
            {
                "timestamp": "2026-02-14T10:32:21Z",
                "level": "INFO",
                "service": "user-service",
                "event": "request_started",
                "message": "User login request"
            }
        ]
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 400, "Should reject missing request_id"

def test_timeline_invalid_timestamp():
    """Test timeline with invalid timestamp"""
    print("\n🧪 Test 7: Timeline with invalid timestamp")
    payload = {
        "logs": [
            {
                "timestamp": "2026-02-14T10:32:21Z",
                "level": "INFO",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_started",
                "message": "User login request"
            },
            {
                "timestamp": "invalid-date",
                "level": "ERROR",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_failed",
                "message": "Request failed"
            }
        ],
        "request_id": "req-123",
        "sort_order": "asc"
    }
    response = requests.post(f"{BASE_URL}/timeline", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    # Should either reject or skip invalid timestamp
    assert response.status_code in [200, 400], "Should handle invalid timestamp"

def test_empty_message():
    """Test with empty message"""
    print("\n🧪 Test 8: Empty message")
    payload = {
        "logs": [
            {
                "timestamp": "2026-02-14T10:32:21Z",
                "level": "INFO",
                "service": "user-service",
                "request_id": "req-123",
                "event": "request_started",
                "message": ""
            }
        ],
        "request_id": "req-123"
    }
    response = requests.post(f"{BASE_URL}/correlate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    assert response.status_code == 422, "Should reject empty message"

if __name__ == "__main__":
    print("=" * 60)
    print("🧪 Testing Edge Cases & Error Handling")
    print("=" * 60)
    
    try:
        test_empty_request_id()
        test_null_request_id()
        test_invalid_timestamp()
        test_blank_timestamp()
        test_empty_logs()
        test_no_request_id_anywhere()
        test_timeline_invalid_timestamp()
        test_empty_message()
        
        print("\n" + "=" * 60)
        print("✅ All edge case tests completed!")
        print("=" * 60)
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Server not running. Start the server first:")
        print("   python app.py")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

