"""
Team 2 - AI-Assisted Root Cause Analyzer
Python Service (FastAPI)
APIs: /correlate, /timeline, /rca
"""

import logging
import json
import uuid
import re
import os
import requests
import sqlite3
import threading
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status

# Load environment variables from .env file
load_dotenv()
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, validator, ValidationError
from typing import List, Optional, Dict, Any
from datetime import datetime

app = FastAPI(
    title="Root Cause Analyzer - Python Service",
    description="Correlation, Timeline, and Root Cause Analysis APIs",
    version="1.0.0"
)

# ==================== Database Setup ====================

# SQLite database file
DB_FILE = "logs_history.db"
_db_lock = threading.Lock()


def init_db():
    """Initialize database tables"""
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = conn.cursor()
        
        # Create log_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                endpoint TEXT,
                timestamp TEXT,
                log_entry TEXT,
                correlation_key TEXT
            )
        """)
        
        # Create api_request_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_request_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT,
                request_id TEXT,
                timestamp TEXT,
                log_count INTEGER,
                status_code INTEGER,
                response_summary TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_request_id ON log_history(request_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_endpoint ON log_history(endpoint)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_history(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_endpoint ON api_request_history(endpoint)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_request_id ON api_request_history(request_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_timestamp ON api_request_history(timestamp)")
        
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Failed to initialize database: {str(e)}")


def save_logs_to_db(endpoint: str, logs: List[LogEntry], correlation_key: Optional[str] = None, request_id: Optional[str] = None):
    """Save logs to database (non-blocking)"""
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        for log in logs:
            log_entry = {
                "timestamp": log.timestamp,
                "level": log.level,
                "service": log.service,
                "request_id": log.request_id,
                "event": log.event,
                "message": log.message,
                "error_code": log.error_code,
                "metadata": log.metadata
            }
            
            cursor.execute("""
                INSERT INTO log_history (request_id, endpoint, timestamp, log_entry, correlation_key)
                VALUES (?, ?, ?, ?, ?)
            """, (
                log.request_id or request_id,
                endpoint,
                timestamp,
                json.dumps(log_entry),
                correlation_key or log.request_id
            ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Failed to save logs to database: {str(e)}")


def save_api_request_to_db(endpoint: str, request_id: Optional[str] = None, 
                           log_count: int = 0, status_code: int = 200, response_summary: Optional[Dict] = None):
    """Save API request to database (non-blocking)"""
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat() + "Z"
        response_summary_json = json.dumps(response_summary) if response_summary else None
        
        cursor.execute("""
            INSERT INTO api_request_history (endpoint, request_id, timestamp, log_count, status_code, response_summary)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (endpoint, request_id, timestamp, log_count, status_code, response_summary_json))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Failed to save API request to database: {str(e)}")


# Initialize database on startup
init_db()

# Enable CORS for frontend/Java service communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For hackathon - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== Structured Logging Setup ====================

class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "service": "root-cause-analyzer",
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add correlation_id if present
        if hasattr(record, 'correlation_id'):
            log_record["correlation_id"] = record.correlation_id
            log_record["request_id"] = record.correlation_id
        
        # Add any extra fields
        if hasattr(record, 'extra_fields'):
            log_record.update(record.extra_fields)
        
        return json.dumps(log_record)


class CorrelationAdapter(logging.LoggerAdapter):
    """Logger adapter to inject correlation IDs"""
    def process(self, msg, kwargs):
        if 'correlation_id' not in kwargs.get('extra', {}):
            kwargs.setdefault('extra', {})['correlation_id'] = self.extra.get('correlation_id')
        return msg, kwargs


# Setup logger
logger = logging.getLogger("root-cause-analyzer")
logger.setLevel(logging.DEBUG)

# Console handler with JSON format
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(JsonFormatter())

# File handler with JSON format (for hackathon)
file_handler = logging.FileHandler("app.log")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(JsonFormatter())

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Prevent duplicate logs
logger.propagate = False

# Serve static files (frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ==================== Exception Handlers ====================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle malformed/invalid requests"""
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    req_logger = get_logger_with_correlation(correlation_id)
    
    # Sanitize error details before logging
    errors = []
    for error in exc.errors():
        sanitized_error = {
            "field": error.get("loc", []),
            "message": mask_sensitive_data(str(error.get("msg", ""))),
            "type": error.get("type", "")
        }
        errors.append(sanitized_error)
    
    req_logger.warn("Validation error", extra={"extra_fields": {
        "path": str(request.url.path),
        "errors": errors
    }})
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Request validation failed",
            "errors": errors[:5]  # Limit error details
        }
    )


@app.exception_handler(ValidationError)
async def pydantic_validation_handler(request: Request, exc: ValidationError):
    """Handle Pydantic validation errors"""
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    req_logger = get_logger_with_correlation(correlation_id)
    
    req_logger.warn("Pydantic validation error", extra={"extra_fields": {
        "path": str(request.url.path),
        "error": mask_sensitive_data(str(exc))
    }})
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": "Invalid data format",
            "error": "Request data does not match expected schema"
        }
    )


def get_logger_with_correlation(correlation_id: Optional[str] = None):
    """Get logger with correlation ID"""
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
    return CorrelationAdapter(logger, {"correlation_id": correlation_id})


# Middleware to log requests with correlation IDs and validate request size
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with correlation IDs and validate request size"""
    # Extract correlation ID from header or generate one
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    req_logger = get_logger_with_correlation(correlation_id)
    
    # Check request size (for POST requests)
    if request.method == "POST":
        content_length = request.headers.get("content-length")
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)
            if size_mb > 100:  # 100MB limit
                req_logger.warn("Request too large", extra={"extra_fields": {
                    "size_mb": size_mb,
                    "limit_mb": 100
                }})
                raise HTTPException(
                    status_code=413,
                    detail=f"Request payload too large. Maximum 100MB allowed, received {size_mb:.2f}MB"
                )
    
    # Log request (sanitized)
    req_logger.info(
        f"Request received: {request.method} {request.url.path}",
        extra={"extra_fields": {
            "method": request.method,
            "path": str(request.url.path),
            "client": request.client.host if request.client else None,
            "content_length": request.headers.get("content-length")
        }}
    )
    
    try:
        response = await call_next(request)
        
        # Log response
        req_logger.info(
            f"Request completed: {request.method} {request.url.path} - Status: {response.status_code}",
            extra={"extra_fields": {
                "method": request.method,
                "path": str(request.url.path),
                "status_code": response.status_code
            }}
        )
        
        # Add correlation ID to response header
        response.headers["X-Correlation-ID"] = correlation_id
        return response
    
    except HTTPException as e:
        req_logger.warn(
            f"HTTP error: {request.method} {request.url.path} - {e.status_code}: {mask_sensitive_data(e.detail)}",
            extra={"extra_fields": {
                "method": request.method,
                "path": str(request.url.path),
                "status_code": e.status_code,
                "error": mask_sensitive_data(e.detail)
            }}
        )
        raise
    except Exception as e:
        req_logger.error(
            f"Request failed: {request.method} {request.url.path} - Error: {mask_sensitive_data(str(e))}",
            extra={"extra_fields": {
                "method": request.method,
                "path": str(request.url.path),
                "error": mask_sensitive_data(str(e))
            }}
        )
        raise HTTPException(status_code=500, detail="Internal server error")


# ==================== Configuration & Limits ====================

# Security and performance limits
MAX_LOGS_PER_REQUEST = 10000  # Maximum logs per API request
MAX_MESSAGE_LENGTH = 10000  # Maximum message length
MAX_SERVICE_NAME_LENGTH = 200

# OpenRouter API Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "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")
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
USE_LLM = os.getenv("USE_LLM", "true").lower() == "true"  # Set to false to disable LLM

SENSITIVE_PATTERNS = [
    r'password["\s:=]+([^\s"\'<>]+)',
    r'pwd["\s:=]+([^\s"\'<>]+)',
    r'passwd["\s:=]+([^\s"\'<>]+)',
    r'token["\s:=]+([^\s"\'<>]+)',
    r'api[_-]?key["\s:=]+([^\s"\'<>]+)',
    r'secret["\s:=]+([^\s"\'<>]+)',
    r'authorization["\s:=]+([^\s"\'<>]+)',
    r'bearer\s+([a-zA-Z0-9\-_\.]+)',
    r'credit[_\s]?card["\s:=]+([0-9\s\-]+)',
    r'cc[_\s]?number["\s:=]+([0-9\s\-]+)',
    r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',  # Credit card pattern
    r'ssn["\s:=]+([0-9\-]+)',
    r'social[_\s]?security["\s:=]+([0-9\-]+)',
]


# ==================== Sensitive Data Masking ====================

def mask_sensitive_data(text: str) -> str:
    """Mask sensitive information in text"""
    if not text or not isinstance(text, str):
        return text
    
    masked = text
    for pattern in SENSITIVE_PATTERNS:
        masked = re.sub(pattern, r'[REDACTED]', masked, flags=re.IGNORECASE)
    
    return masked


def sanitize_log_entry(log_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize log entry to remove sensitive data"""
    sanitized = log_entry.copy()
    
    # Mask sensitive fields
    if 'message' in sanitized:
        sanitized['message'] = mask_sensitive_data(str(sanitized['message']))
    
    if 'metadata' in sanitized and isinstance(sanitized['metadata'], dict):
        sanitized_metadata = {}
        for key, value in sanitized['metadata'].items():
            # Mask sensitive keys
            if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key', 'auth']):
                sanitized_metadata[key] = '[REDACTED]'
            else:
                sanitized_metadata[key] = mask_sensitive_data(str(value)) if isinstance(value, str) else value
        sanitized['metadata'] = sanitized_metadata
    
    return sanitized


# ==================== Data Models ====================

class LogEntry(BaseModel):
    """Canonical log schema with validation"""
    timestamp: str
    level: str = Field(..., pattern="^(DEBUG|INFO|WARN|ERROR|FATAL)$")
    service: str = Field(..., max_length=MAX_SERVICE_NAME_LENGTH)
    request_id: Optional[str] = None
    event: str
    message: str = Field(..., max_length=MAX_MESSAGE_LENGTH)
    error_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v is None:
            raise ValueError('Timestamp is required and cannot be None')
        if not isinstance(v, str):
            raise ValueError(f'Timestamp must be a string, got {type(v).__name__}')
        v = v.strip()
        if len(v) == 0:
            raise ValueError('Timestamp cannot be empty or blank')
        
        # Try to parse timestamp to validate format
        try:
            # Handle various timestamp formats
            timestamp_str = v.replace('Z', '+00:00')
            datetime.fromisoformat(timestamp_str)
        except (ValueError, AttributeError) as e:
            raise ValueError(
                f'Invalid timestamp format: "{v}". '
                f'Expected ISO 8601 format (e.g., 2026-02-14T10:32:21Z or 2026-02-14T10:32:21+00:00). '
                f'Error: {str(e)}'
            )
        return v
    
    @validator('message')
    def validate_message(cls, v):
        if not v or not isinstance(v, str) or len(v.strip()) == 0:
            raise ValueError('Message cannot be empty')
        return v.strip()
    
    @validator('service')
    def validate_service(cls, v):
        if not v or not isinstance(v, str) or len(v.strip()) == 0:
            raise ValueError('Service name cannot be empty')
        return v.strip()
    
    @validator('event')
    def validate_event(cls, v):
        if not v or not isinstance(v, str) or len(v.strip()) == 0:
            raise ValueError('Event cannot be empty')
        return v.strip()
    
    @validator('request_id')
    def validate_request_id(cls, v):
        if v is not None and (not isinstance(v, str) or len(v.strip()) == 0):
            return None  # Convert empty string to None
        return v.strip() if v and isinstance(v, str) else v
    
    
    class Config:
        extra = "forbid"  # Reject unknown fields


class CorrelateRequest(BaseModel):
    """Request for /correlate endpoint"""
    logs: List[LogEntry] = Field(..., max_items=MAX_LOGS_PER_REQUEST)
    request_id: Optional[str] = None
    
    @validator('logs')
    def validate_logs_count(cls, v):
        if v is None:
            raise ValueError('Logs array is required')
        if len(v) > MAX_LOGS_PER_REQUEST:
            raise ValueError(f'Maximum {MAX_LOGS_PER_REQUEST} logs allowed per request')
        if len(v) == 0:
            raise ValueError('At least one log entry is required')
        return v
    
    @validator('request_id')
    def validate_request_id(cls, v):
        if v is not None:
            if not isinstance(v, str):
                return None
            v = v.strip()
            if len(v) == 0:
                return None
        return v


class CorrelateResponse(BaseModel):
    """Response from /correlate endpoint"""
    request_id: str
    correlated_logs: List[LogEntry]
    total_count: int


class TimelineRequest(BaseModel):
    """Request for /timeline endpoint"""
    logs: List[LogEntry] = Field(..., max_items=MAX_LOGS_PER_REQUEST)
    request_id: Optional[str] = None
    sort_order: Optional[str] = Field("asc", pattern="^(asc|desc)$")  # "asc" = oldest to newest, "desc" = newest to oldest
    
    @validator('logs')
    def validate_logs_count(cls, v):
        if v is None:
            raise ValueError('Logs array is required')
        if len(v) > MAX_LOGS_PER_REQUEST:
            raise ValueError(f'Maximum {MAX_LOGS_PER_REQUEST} logs allowed per request')
        if len(v) == 0:
            raise ValueError('At least one log entry is required')
        return v
    
    @validator('sort_order')
    def validate_sort_order(cls, v):
        if v is None:
            return "asc"
        if not isinstance(v, str):
            return "asc"
        v = v.strip().lower()
        if v not in ["asc", "desc"]:
            raise ValueError('sort_order must be "asc" (oldest to newest) or "desc" (newest to oldest)')
        return v
    
    @validator('request_id')
    def validate_request_id(cls, v):
        if v is not None:
            if not isinstance(v, str):
                return None
            v = v.strip()
            if len(v) == 0:
                return None
        return v


class TimelineResponse(BaseModel):
    """Response from /timeline endpoint"""
    request_id: str
    timeline: List[LogEntry]
    duration_ms: Optional[float] = None
    first_event: Optional[str] = None
    last_event: Optional[str] = None
    sort_order: str  # "asc" or "desc"


class RCARequest(BaseModel):
    """Request for /rca endpoint"""
    logs: List[LogEntry] = Field(..., max_items=MAX_LOGS_PER_REQUEST)
    request_id: Optional[str] = None
    timeline: Optional[List[LogEntry]] = Field(None, max_items=MAX_LOGS_PER_REQUEST)
    
    @validator('logs')
    def validate_logs_count(cls, v):
        if v is None:
            raise ValueError('Logs array is required')
        if len(v) > MAX_LOGS_PER_REQUEST:
            raise ValueError(f'Maximum {MAX_LOGS_PER_REQUEST} logs allowed per request')
        if len(v) == 0:
            raise ValueError('At least one log entry is required')
        return v
    
    @validator('timeline')
    def validate_timeline_count(cls, v):
        if v is not None:
            if len(v) > MAX_LOGS_PER_REQUEST:
                raise ValueError(f'Maximum {MAX_LOGS_PER_REQUEST} logs allowed in timeline')
        return v
    
    @validator('request_id')
    def validate_request_id(cls, v):
        if v is not None:
            if not isinstance(v, str):
                return None
            v = v.strip()
            if len(v) == 0:
                return None
        return v


class RootCause(BaseModel):
    """Root cause hypothesis"""
    cause: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str]  # Log entries or patterns that support this cause
    category: str  # e.g., "timeout", "service_failure", "validation_error"


class RCAResponse(BaseModel):
    """Response from /rca endpoint"""
    request_id: str
    root_causes: List[RootCause]
    failure_propagation: List[Dict[str, Any]]  # Chain of failures
    summary: str  # LLM-generated explanation
    analysis_timestamp: str


# ==================== API Endpoints ====================

@app.get("/", include_in_schema=False)
def root():
    """Serve frontend UI"""
    return FileResponse("static/index.html")

@app.get("/ui", include_in_schema=False)
def ui():
    """Alternative route to frontend UI"""
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    """Health check endpoint"""
    return {
        "service": "Root Cause Analyzer - Python Service",
        "status": "running",
        "apis": ["/correlate", "/timeline", "/rca", "/history"],
        "docs": "/docs"
    }


@app.get("/history")
def get_history(
    endpoint: Optional[str] = None,
    request_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Get log history from database
    
    Query parameters:
    - endpoint: Filter by endpoint ('correlate', 'timeline', 'rca')
    - request_id: Filter by request_id
    - limit: Maximum number of records (default: 100, max: 1000)
    - offset: Skip records for pagination (default: 0)
    """
    try:
        limit = min(limit, 1000)  # Cap at 1000
        limit = max(limit, 1)  # At least 1
        
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Build query for log history
        log_query = "SELECT * FROM log_history WHERE 1=1"
        log_params = []
        
        if endpoint:
            log_query += " AND endpoint = ?"
            log_params.append(endpoint)
        if request_id:
            log_query += " AND request_id = ?"
            log_params.append(request_id)
        
        log_query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        log_params.extend([limit, offset])
        
        cursor.execute(log_query, log_params)
        log_rows = cursor.fetchall()
        
        # Get total count
        count_query = "SELECT COUNT(*) FROM log_history WHERE 1=1"
        count_params = []
        if endpoint:
            count_query += " AND endpoint = ?"
            count_params.append(endpoint)
        if request_id:
            count_query += " AND request_id = ?"
            count_params.append(request_id)
        
        cursor.execute(count_query, count_params)
        total_count = cursor.fetchone()[0]
        
        # Build query for API request history
        api_query = "SELECT * FROM api_request_history WHERE 1=1"
        api_params = []
        
        if endpoint:
            api_query += " AND endpoint = ?"
            api_params.append(endpoint)
        if request_id:
            api_query += " AND request_id = ?"
            api_params.append(request_id)
        
        api_query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        api_params.extend([limit, offset])
        
        cursor.execute(api_query, api_params)
        api_rows = cursor.fetchall()
        
        conn.close()
        
        return {
            "logs": [
                {
                    "id": row["id"],
                    "request_id": row["request_id"],
                    "endpoint": row["endpoint"],
                    "timestamp": row["timestamp"],
                    "log_entry": json.loads(row["log_entry"]) if row["log_entry"] else None,
                    "correlation_key": row["correlation_key"]
                }
                for row in log_rows
            ],
            "api_requests": [
                {
                    "id": row["id"],
                    "endpoint": row["endpoint"],
                    "request_id": row["request_id"],
                    "timestamp": row["timestamp"],
                    "log_count": row["log_count"],
                    "status_code": row["status_code"],
                    "response_summary": json.loads(row["response_summary"]) if row["response_summary"] else None
                }
                for row in api_rows
            ],
            "total_logs": total_count,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve history: {str(e)}")


@app.post("/correlate", response_model=CorrelateResponse)
def correlate_logs(request: CorrelateRequest, req: Request):
    """
    Correlate logs by request_id
    
    Links events that belong to the same request
    """
    correlation_id = req.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    req_logger = get_logger_with_correlation(correlation_id)
    
    try:
        # Validate and sanitize logs before processing
        log_count = len(request.logs) if request.logs else 0
        
        req_logger.info("Correlate request received", extra={"extra_fields": {
            "log_count": log_count
        }})
        
        # Check for large datasets
        if log_count > 1000:
            req_logger.warn("Large dataset received", extra={"extra_fields": {
                "log_count": log_count,
                "warning": "Processing large dataset may take time"
            }})
        
        # Validate logs array
        if not request.logs:
            req_logger.warn("Correlate request with no logs")
            raise HTTPException(status_code=400, detail="No logs provided")
        
        # Validate each log entry
        for i, log in enumerate(request.logs):
            if not log.timestamp or not log.timestamp.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: timestamp is required and cannot be empty"
                )
            if not log.service or not log.service.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: service is required and cannot be empty"
                )
            if not log.message or not log.message.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: message is required and cannot be empty"
                )
        
        # Determine correlation key (handle None, empty string, blank)
        correlation_key = None
        
        # Check request-level parameter (strip whitespace, handle None)
        if request.request_id and isinstance(request.request_id, str) and request.request_id.strip():
            correlation_key = request.request_id.strip()
        
        # If not provided, try to extract from logs
        if not correlation_key:
            for log in request.logs:
                if log.request_id and isinstance(log.request_id, str) and log.request_id.strip():
                    correlation_key = log.request_id.strip()
                    break
        
        if not correlation_key:
            raise HTTPException(
                status_code=400, 
                detail="No request_id provided or found in logs. At least one log entry must have a valid request_id."
            )
        
        # Filter logs by correlation key (handle None/empty values)
        correlated = []
        for log in request.logs:
            log_request_id = log.request_id.strip() if log.request_id and isinstance(log.request_id, str) else None
            
            if log_request_id == correlation_key:
                correlated.append(log)
        
        # Sanitize logs before returning (remove sensitive data)
        # Note: For large datasets, we sanitize on-demand rather than all at once
        
        result = CorrelateResponse(
            request_id=correlation_key,
            correlated_logs=correlated,
            total_count=len(correlated)
        )
        
        req_logger.info("Correlate completed successfully", extra={"extra_fields": {
            "request_id": correlation_key,
            "correlated_count": len(correlated)
        }})
        
        # Save to database (non-blocking)
        try:
            save_logs_to_db("correlate", correlated, correlation_key, request.request_id)
            save_api_request_to_db("correlate", correlation_key, len(correlated), 200, {
                "total_count": len(correlated)
            })
        except Exception as e:
            req_logger.warn(f"Failed to save to database: {str(e)}")
        
        return result
    
    except HTTPException as e:
        req_logger.error(f"Correlate request failed: {e.detail}", extra={"extra_fields": {
            "status_code": e.status_code,
            "error": e.detail
        }})
        raise
    except Exception as e:
        req_logger.error(f"Correlate request error: {str(e)}", extra={"extra_fields": {
            "error": str(e)
        }})
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/timeline", response_model=TimelineResponse)
def create_timeline(request: TimelineRequest, req: Request):
    """
    Create ordered execution timeline from logs
    
    Orders events chronologically for a given request.
    
    - sort_order="asc" (default): Oldest to newest (chronological order)
    - sort_order="desc": Newest to oldest (reverse chronological order)
    """
    correlation_id = req.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    req_logger = get_logger_with_correlation(correlation_id)
    
    try:
        req_logger.info("Timeline request received", extra={"extra_fields": {
            "log_count": len(request.logs) if request.logs else 0
        }})
        # Validate logs array
        if not request.logs:
            raise HTTPException(status_code=400, detail="No logs provided")
        
        # Validate each log entry
        for i, log in enumerate(request.logs):
            if not log.timestamp or not log.timestamp.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: timestamp is required and cannot be empty"
                )
            if not log.service or not log.service.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: service is required and cannot be empty"
                )
            if not log.message or not log.message.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: message is required and cannot be empty"
                )
        
        # Determine correlation key (handle None, empty string, blank)
        correlation_key = None
        
        # Check request-level parameter
        if request.request_id and isinstance(request.request_id, str) and request.request_id.strip():
            correlation_key = request.request_id.strip()
        
        # If not provided, try to extract from logs
        if not correlation_key:
            for log in request.logs:
                if log.request_id and isinstance(log.request_id, str) and log.request_id.strip():
                    correlation_key = log.request_id.strip()
                    break
        
        if not correlation_key:
            raise HTTPException(
                status_code=400,
                detail="No request_id provided or found in logs. At least one log entry must have a valid request_id."
            )
        
        # Filter logs by correlation key (handle None/empty values)
        timeline_logs = []
        for log in request.logs:
            log_request_id = log.request_id.strip() if log.request_id and isinstance(log.request_id, str) else None
            if log_request_id == correlation_key:
                timeline_logs.append(log)
        
        if not timeline_logs:
            raise HTTPException(
                status_code=404,
                detail=f"No logs found for request_id: {correlation_key}"
            )
        
        # Validate and parse timestamps
        valid_timeline_logs = []
        invalid_timestamps = []
        
        for i, log in enumerate(timeline_logs):
            try:
                # Validate timestamp format
                datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                valid_timeline_logs.append(log)
            except (ValueError, AttributeError) as e:
                invalid_timestamps.append({
                    "index": i,
                    "timestamp": log.timestamp,
                    "error": str(e)
                })
        
        if invalid_timestamps:
            req_logger.warn("Invalid timestamps found", extra={"extra_fields": {
                "invalid_count": len(invalid_timestamps),
                "invalid_timestamps": invalid_timestamps[:5]  # Log first 5
            }})
            # Continue with valid logs, but log the issue
        
        if not valid_timeline_logs:
            raise HTTPException(
                status_code=400,
                detail=f"All timestamps are invalid. Cannot create timeline. Invalid timestamps: {invalid_timestamps[:3]}"
            )
        
        # Sort by timestamp (ascending or descending based on sort_order)
        sort_order = request.sort_order or "asc"
        
        def safe_timestamp_sort(log):
            """Safe timestamp sorting with fallback"""
            try:
                return datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
            except:
                # If parsing fails, use string comparison as fallback
                return log.timestamp
        
        if sort_order == "desc":
            valid_timeline_logs.sort(key=safe_timestamp_sort, reverse=True)
        else:
            valid_timeline_logs.sort(key=safe_timestamp_sort)
        
        # Calculate duration (always based on actual first and last, regardless of sort order)
        sorted_by_time = sorted(valid_timeline_logs, key=safe_timestamp_sort)
        duration_ms = None
        first_event = sorted_by_time[0].timestamp if sorted_by_time else None
        last_event = sorted_by_time[-1].timestamp if sorted_by_time else None
        
        if first_event and last_event:
            try:
                first = datetime.fromisoformat(first_event.replace('Z', '+00:00'))
                last = datetime.fromisoformat(last_event.replace('Z', '+00:00'))
                duration_ms = (last - first).total_seconds() * 1000
            except (ValueError, AttributeError) as e:
                req_logger.warn(f"Duration calculation failed: {str(e)}")
                duration_ms = None
        
        timeline_logs = valid_timeline_logs
        
        result = TimelineResponse(
            request_id=correlation_key,
            timeline=timeline_logs,
            duration_ms=duration_ms,
            first_event=first_event,
            last_event=last_event,
            sort_order=sort_order
        )
        
        req_logger.info("Timeline created successfully", extra={"extra_fields": {
            "request_id": correlation_key,
            "timeline_count": len(timeline_logs),
            "duration_ms": duration_ms
        }})
        
        # Save to database (non-blocking)
        try:
            save_logs_to_db("timeline", timeline_logs, correlation_key, correlation_key)
            save_api_request_to_db("timeline", correlation_key, len(timeline_logs), 200, {
                "duration_ms": duration_ms,
                "sort_order": sort_order
            })
        except Exception as e:
            req_logger.warn(f"Failed to save to database: {str(e)}")
        
        return result
    
    except HTTPException as e:
        req_logger.error(f"Timeline request failed: {e.detail}", extra={"extra_fields": {
            "status_code": e.status_code,
            "error": e.detail
        }})
        raise
    except Exception as e:
        req_logger.error(f"Timeline request error: {str(e)}", extra={"extra_fields": {
            "error": str(e)
        }})
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rca", response_model=RCAResponse)
def root_cause_analysis(request: RCARequest, req: Request):
    """
    Root Cause Analysis - Detect failure propagation and suggest root causes
    
    Uses rule-based analysis + LLM for explanation
    """
    correlation_id = req.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    req_logger = get_logger_with_correlation(correlation_id)
    
    try:
        req_logger.info("RCA request received", extra={"extra_fields": {
            "log_count": len(request.logs) if request.logs else 0
        }})
        # Validate logs array
        if not request.logs:
            raise HTTPException(status_code=400, detail="No logs provided")
        
        # Validate each log entry
        for i, log in enumerate(request.logs):
            if not log.timestamp or not log.timestamp.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: timestamp is required and cannot be empty"
                )
            if not log.service or not log.service.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: service is required and cannot be empty"
                )
            if not log.message or not log.message.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Log entry {i}: message is required and cannot be empty"
                )
        
        # Determine request_id (handle None, empty string, blank)
        correlation_key = None
        
        # Check request-level parameter
        if request.request_id and isinstance(request.request_id, str) and request.request_id.strip():
            correlation_key = request.request_id.strip()
        
        # If not provided, try to extract from logs
        if not correlation_key:
            for log in request.logs:
                if log.request_id and isinstance(log.request_id, str) and log.request_id.strip():
                    correlation_key = log.request_id.strip()
                    break
        
        if not correlation_key:
            raise HTTPException(
                status_code=400,
                detail="No request_id provided or found in logs. At least one log entry must have a valid request_id."
            )
        
        # Use provided timeline or create one (with validation)
        timeline = request.timeline
        if not timeline:
            timeline_logs = []
            for log in request.logs:
                log_request_id = log.request_id.strip() if log.request_id and isinstance(log.request_id, str) else None
                if log_request_id == correlation_key:
                    timeline_logs.append(log)
            
            # Validate timestamps before sorting
            valid_timeline_logs = []
            for log in timeline_logs:
                try:
                    datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                    valid_timeline_logs.append(log)
                except (ValueError, AttributeError):
                    req_logger.warn(f"Invalid timestamp in log: {log.timestamp}")
                    # Skip invalid timestamps but continue processing
            
            if valid_timeline_logs:
                valid_timeline_logs.sort(key=lambda x: x.timestamp)
                timeline = valid_timeline_logs
            else:
                raise HTTPException(
                    status_code=400,
                    detail="No valid logs with parseable timestamps found for timeline creation"
                )
        
        # Analyze for root causes using rules
        root_causes = _analyze_root_causes(timeline)
        
        # Detect failure propagation
        failure_propagation = _detect_failure_propagation(timeline)
        
        # Generate LLM explanation (for hackathon: template-based, can be replaced with actual LLM)
        summary = _generate_rca_summary(root_causes, failure_propagation, timeline)
        
        result = RCAResponse(
            request_id=correlation_key,
            root_causes=root_causes,
            failure_propagation=failure_propagation,
            summary=summary,
            analysis_timestamp=datetime.utcnow().isoformat() + "Z"
        )
        
        req_logger.info("RCA analysis completed", extra={"extra_fields": {
            "request_id": correlation_key,
            "root_cause_count": len(root_causes),
            "propagation_steps": len(failure_propagation)
        }})
        
        # Save to database (non-blocking)
        try:
            save_logs_to_db("rca", timeline, correlation_key, correlation_key)
            save_api_request_to_db("rca", correlation_key, len(timeline), 200, {
                "root_cause_count": len(root_causes),
                "propagation_steps": len(failure_propagation)
            })
        except Exception as e:
            req_logger.warn(f"Failed to save to database: {str(e)}")
        
        return result
    
    except HTTPException as e:
        req_logger.error(f"RCA request failed: {e.detail}", extra={"extra_fields": {
            "status_code": e.status_code,
            "error": e.detail
        }})
        raise
    except Exception as e:
        req_logger.error(f"RCA request error: {str(e)}", extra={"extra_fields": {
            "error": str(e)
        }})
        raise HTTPException(status_code=500, detail=str(e))


# ==================== RCA Helper Functions ====================

def _analyze_root_causes(timeline: List[LogEntry]) -> List[RootCause]:
    """Rule-based root cause analysis"""
    root_causes = []
    
    # Rule 1: Timeout errors
    timeout_logs = [log for log in timeline if "timeout" in log.message.lower() or 
                    (log.error_code and "timeout" in log.error_code.lower())]
    if timeout_logs:
        root_causes.append(RootCause(
            cause="Service timeout - External service or gateway did not respond in time",
            confidence=0.85,
            evidence=[f"{log.service}: {log.message}" for log in timeout_logs[:3]],
            category="timeout"
        ))
    
    # Rule 2: Service unavailable
    unavailable_logs = [log for log in timeline if "unavailable" in log.message.lower() or 
                        log.level == "ERROR" and "service" in log.message.lower()]
    if unavailable_logs:
        root_causes.append(RootCause(
            cause="Service unavailable - Downstream service is not responding",
            confidence=0.90,
            evidence=[f"{log.service}: {log.message}" for log in unavailable_logs[:3]],
            category="service_failure"
        ))
    
    # Rule 3: Validation errors
    validation_logs = [log for log in timeline if "validation" in log.message.lower() or 
                       "invalid" in log.message.lower()]
    if validation_logs:
        root_causes.append(RootCause(
            cause="Validation error - Invalid input or data format",
            confidence=0.75,
            evidence=[f"{log.service}: {log.message}" for log in validation_logs[:3]],
            category="validation_error"
        ))
    
    # Rule 4: Authentication/Authorization errors
    auth_logs = [log for log in timeline if "auth" in log.message.lower() or 
                 "unauthorized" in log.message.lower() or "forbidden" in log.message.lower()]
    if auth_logs:
        root_causes.append(RootCause(
            cause="Authentication/Authorization failure - Invalid credentials or insufficient permissions",
            confidence=0.80,
            evidence=[f"{log.service}: {log.message}" for log in auth_logs[:3]],
            category="auth_error"
        ))
    
    # Rule 5: Database/Connection errors
    db_logs = [log for log in timeline if "database" in log.message.lower() or 
               "connection" in log.message.lower() or "sql" in log.message.lower()]
    if db_logs:
        root_causes.append(RootCause(
            cause="Database connection issue - Unable to connect or query database",
            confidence=0.85,
            evidence=[f"{log.service}: {log.message}" for log in db_logs[:3]],
            category="database_error"
        ))
    
    # Rule 6: High error rate pattern
    error_logs = [log for log in timeline if log.level in ["ERROR", "FATAL"]]
    if len(error_logs) >= 3:
        root_causes.append(RootCause(
            cause="Cascading failures - Multiple errors indicate systemic issue",
            confidence=0.70,
            evidence=[f"{log.service}: {log.message}" for log in error_logs[:3]],
            category="cascading_failure"
        ))
    
    # If no specific pattern found, provide generic analysis
    if not root_causes and error_logs:
        root_causes.append(RootCause(
            cause="Unknown error pattern - Requires further investigation",
            confidence=0.50,
            evidence=[f"{log.service}: {log.message}" for log in error_logs[:3]],
            category="unknown"
        ))
    
    # Sort by confidence (highest first)
    root_causes.sort(key=lambda x: x.confidence, reverse=True)
    
    return root_causes


def _detect_failure_propagation(timeline: List[LogEntry]) -> List[Dict[str, Any]]:
    """Detect how failures propagate through the system"""
    propagation = []
    
    # Group by service
    service_logs = {}
    for log in timeline:
        if log.service not in service_logs:
            service_logs[log.service] = []
        service_logs[log.service].append(log)
    
    # Find error sequence
    error_sequence = []
    for log in timeline:
        if log.level in ["ERROR", "FATAL", "WARN"]:
            error_sequence.append({
                "service": log.service,
                "timestamp": log.timestamp,
                "level": log.level,
                "event": log.event,
                "message": log.message,
                "error_code": log.error_code
            })
    
    # Identify propagation chain
    if len(error_sequence) > 1:
        for i in range(len(error_sequence) - 1):
            propagation.append({
                "from": error_sequence[i]["service"],
                "to": error_sequence[i + 1]["service"],
                "time_gap_ms": _calculate_time_gap(
                    error_sequence[i]["timestamp"],
                    error_sequence[i + 1]["timestamp"]
                ),
                "trigger": error_sequence[i]["message"]
            })
    
    return propagation


def _calculate_time_gap(timestamp1: str, timestamp2: str) -> Optional[float]:
    """Calculate time gap between two timestamps in milliseconds"""
    try:
        t1 = datetime.fromisoformat(timestamp1.replace('Z', '+00:00'))
        t2 = datetime.fromisoformat(timestamp2.replace('Z', '+00:00'))
        return (t2 - t1).total_seconds() * 1000
    except:
        return None


def _generate_rca_summary(
    root_causes: List[RootCause],
    failure_propagation: List[Dict[str, Any]],
    timeline: List[LogEntry]
) -> str:
    """
    Generate human-readable RCA summary
    Uses OpenRouter LLM API if available, falls back to intelligent rule-based local analysis
    """
    if not root_causes:
        return "No root causes identified. System appears to be functioning normally."
    
    # Try LLM first if enabled (with timeout and error handling)
    if USE_LLM and OPENROUTER_API_KEY:
        try:
            logger.info("Attempting LLM API call for RCA summary")
            summary = _generate_rca_summary_llm(root_causes, failure_propagation, timeline)
            logger.info("LLM API call successful")
            return summary
        except requests.exceptions.Timeout:
            logger.warning("LLM API timeout, using local rule-based analysis")
        except requests.exceptions.ConnectionError:
            logger.warning("LLM API connection error, using local rule-based analysis")
        except requests.exceptions.RequestException as e:
            logger.warning(f"LLM API request failed: {str(e)}, using local rule-based analysis")
        except Exception as e:
            logger.warning(f"LLM API call failed: {str(e)}, using local rule-based analysis")
    
    # Always fall back to intelligent local rule-based analysis
    logger.info("Using local rule-based RCA summary generation")
    return _generate_rca_summary_local_rules(root_causes, failure_propagation, timeline)


def _generate_rca_summary_llm(
    root_causes: List[RootCause],
    failure_propagation: List[Dict[str, Any]],
    timeline: List[LogEntry]
) -> str:
    """Generate summary using OpenRouter LLM API"""
    
    # Prepare context for LLM
    root_causes_text = "\n".join([
        f"- {cause.cause} (confidence: {cause.confidence * 100:.0f}%, category: {cause.category})"
        for cause in root_causes[:5]  # Top 5 causes
    ])
    
    evidence_text = "\n".join([
        f"- {evidence}" for cause in root_causes[:3] for evidence in cause.evidence[:2]
    ])
    
    propagation_text = "\n".join([
        f"- {prop['from']} → {prop['to']} ({prop['time_gap_ms']:.0f}ms gap): {prop['trigger'][:100]}"
        for prop in failure_propagation[:5]
    ]) if failure_propagation else "No failure propagation detected"
    
    timeline_summary = f"Total {len(timeline)} events analyzed"
    
    prompt = f"""You are an expert at root cause analysis. Provide a CONCISE, pointed summary (max 200 words).

Root Causes:
{root_causes_text}

Evidence:
{evidence_text}

Failure Chain:
{propagation_text}

Timeline: {timeline_summary}

Provide a brief markdown summary with:
1. Primary root cause (1-2 sentences)
2. Key evidence (bullet points, max 3)
3. Top 3 actionable recommendations

Keep it SHORT and FOCUSED. No fluff."""

    try:
        response = requests.post(
            url=OPENROUTER_API_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "Root Cause Analyzer"
            },
            json={
                "model": "openai/gpt-4o-mini",  # Using cheaper model, can change to gpt-4o or others
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert at analyzing system logs and identifying root causes. Provide clear, actionable insights."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 250
            },
            timeout=10  # 10 second timeout (fail fast)
        )
        
        response.raise_for_status()
        result = response.json()
        
        if "choices" in result and len(result["choices"]) > 0:
            return result["choices"][0]["message"]["content"]
        else:
            raise Exception("Invalid response format from LLM API")
            
    except requests.exceptions.RequestException as e:
        raise Exception(f"LLM API request failed: {str(e)}")
    except Exception as e:
        raise Exception(f"LLM API error: {str(e)}")


def _generate_rca_summary_local_rules(
    root_causes: List[RootCause],
    failure_propagation: List[Dict[str, Any]],
    timeline: List[LogEntry]
) -> str:
    """
    Generate intelligent summary using local rule-based analysis
    This always works even if external APIs are down
    """
    primary_cause = root_causes[0]
    
    # Calculate timeline duration
    duration_seconds = None
    if timeline:
        try:
            first = datetime.fromisoformat(timeline[0].timestamp.replace('Z', '+00:00'))
            last = datetime.fromisoformat(timeline[-1].timestamp.replace('Z', '+00:00'))
            duration_seconds = (last - first).total_seconds()
        except:
            pass
    
    # Count error levels
    error_count = sum(1 for log in timeline if log.level in ["ERROR", "FATAL"])
    warn_count = sum(1 for log in timeline if log.level == "WARN")
    info_count = sum(1 for log in timeline if log.level == "INFO")
    
    # Build concise, pointed summary (max 150 words)
    summary_parts = [
        f"## Root Cause Analysis\n\n",
        f"**Primary Cause:** {primary_cause.cause} ({primary_cause.confidence * 100:.0f}% confidence)\n\n"
    ]
    
    # Brief analysis based on category (1-2 sentences max)
    if primary_cause.category == "timeout":
        summary_parts.append(
            "External service/gateway timeout. Likely due to service overload, network issues, or timeout thresholds too low.\n\n"
        )
    elif primary_cause.category == "service_failure":
        summary_parts.append(
            "Downstream service unavailable. Service may be down, overloaded, or experiencing network partition.\n\n"
        )
    elif primary_cause.category == "validation_error":
        summary_parts.append(
            "Input validation failed. Invalid data format, missing fields, or type mismatches.\n\n"
        )
    elif primary_cause.category == "database_error":
        summary_parts.append(
            "Database connectivity issues. Connection pool exhaustion, server unavailable, or query timeout.\n\n"
        )
    elif primary_cause.category == "cascading_failure":
        summary_parts.append(
            "Systemic failure detected. Initial failure triggered chain reaction across services.\n\n"
        )
    
    # Key Evidence (max 3 items, concise)
    if primary_cause.evidence:
        summary_parts.append("**Key Evidence:**\n")
        for evidence in primary_cause.evidence[:3]:
            summary_parts.append(f"- {evidence}\n")
        summary_parts.append("\n")
    
    # Failure Propagation (one line)
    if failure_propagation:
        chain = " → ".join([f"{prop['from']}→{prop['to']}" for prop in failure_propagation[:3]])
        summary_parts.append(f"**Failure Chain:** {chain}\n\n")
    
    # Top 3 Recommendations (concise, actionable)
    summary_parts.append("**Recommendations:**\n")
    if primary_cause.category == "timeout":
        summary_parts.append(
            "1. Increase timeout thresholds\n"
            "2. Implement retry with exponential backoff\n"
            "3. Add circuit breaker pattern\n\n"
        )
    elif primary_cause.category == "service_failure":
        summary_parts.append(
            "1. Check and restart service\n"
            "2. Verify service dependencies\n"
            "3. Implement health checks\n\n"
        )
    elif primary_cause.category == "validation_error":
        summary_parts.append(
            "1. Review validation rules\n"
            "2. Validate at API gateway\n"
            "3. Improve error messages\n\n"
        )
    elif primary_cause.category == "database_error":
        summary_parts.append(
            "1. Check connection pool\n"
            "2. Verify database status\n"
            "3. Optimize slow queries\n\n"
        )
    else:
        summary_parts.append(
            "1. Review system logs\n"
            "2. Check dependencies\n"
            "3. Monitor metrics\n\n"
        )
    
    return "".join(summary_parts)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

