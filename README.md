# Team 2 - AI-Assisted Root Cause Analyzer

## Team Members
- **Shagun** (Python Developer)
- **Santosh** (Java Developer)

## Architecture

### Python Service (FastAPI)
- Port: `5000`
- APIs: `/correlate`, `/timeline`

### Java Service (Spring Boot)
- Port: `8080`
- API: `/rca`

## Quick Start - Python Service

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Service
```bash
python app.py
```

Or with uvicorn:
```bash
uvicorn app:app --reload --port 5000
```

### 3. Access API Docs
Open browser: `http://localhost:5000/docs`

Automatic Swagger UI with all endpoints!

## API Endpoints

### POST /correlate
Correlate logs by request_id or session_id

**Request:**
```json
{
  "logs": [
    {
      "timestamp": "2026-02-14T10:32:21Z",
      "level": "ERROR",
      "service": "payment-service",
      "request_id": "req-7F3A2",
      "event": "payment_failed",
      "message": "Gateway timeout"
    }
  ],
  "request_id": "req-7F3A2"
}
```

**Response:**
```json
{
  "request_id": "req-7F3A2",
  "correlated_logs": [...],
  "total_count": 5
}
```

### POST /timeline
Create ordered execution timeline

**Request:**
```json
{
  "logs": [...],
  "request_id": "req-7F3A2"
}
```

**Response:**
```json
{
  "request_id": "req-7F3A2",
  "timeline": [...],
  "duration_ms": 1234.5,
  "first_event": "2026-02-14T10:32:21Z",
  "last_event": "2026-02-14T10:32:22Z"
}
```

## Testing

### Using curl:
```bash
curl -X POST http://localhost:5000/correlate \
  -H "Content-Type: application/json" \
  -d '{"logs": [...], "request_id": "req-123"}'
```

### Using Python:
```python
import requests

response = requests.post(
    "http://localhost:5000/correlate",
    json={"logs": [...], "request_id": "req-123"}
)
print(response.json())
```

## Collaboration with Java Service

Python service can call Java service:
```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:8080/rca",
        json={"correlated_logs": [...], "timeline": [...]}
    )
    rca_result = response.json()
```

## Project Structure
```
.
├── app.py                 # FastAPI main application
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── COLLABORATION_STRATEGY.md
```

