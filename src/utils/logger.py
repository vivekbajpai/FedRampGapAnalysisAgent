"""
Logging utilities for FedRamp Gap Analysis Agent.

This module provides structured logging with support for different formats,
log levels, and output destinations.
"""

import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path
import traceback


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output."""
    
    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class LoggerAdapter(logging.LoggerAdapter):
    """Custom logger adapter with additional context."""
    
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log message with extra context."""
        extra = kwargs.get("extra", {})
        if self.extra:
            extra.update(self.extra)
        kwargs["extra"] = {"extra_fields": extra}
        return msg, kwargs


def setup_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    console_output: bool = True
) -> logging.Logger:
    """
    Set up a logger with specified configuration.
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for file logging
        json_format: Use JSON format for logs
        console_output: Enable console output
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    logger.handlers.clear()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        
        if json_format:
            console_handler.setFormatter(JSONFormatter())
        else:
            console_formatter = ColoredFormatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            console_handler.setFormatter(console_formatter)
        
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        
        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_formatter = logging.Formatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
        
        logger.addHandler(file_handler)
    
    return logger


def get_logger(
    name: str,
    context: Optional[Dict[str, Any]] = None
) -> LoggerAdapter:
    """
    Get a logger with optional context.
    
    Args:
        name: Logger name
        context: Optional context dictionary to include in all logs
    
    Returns:
        Logger adapter with context
    """
    logger = logging.getLogger(name)
    return LoggerAdapter(logger, context or {})


class RequestLogger:
    """Logger for HTTP requests with timing and metadata."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        **kwargs
    ):
        """Log HTTP request with metadata."""
        extra = {
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "user_id": user_id,
            "request_id": request_id,
            **kwargs
        }
        
        level = logging.INFO
        if status_code >= 500:
            level = logging.ERROR
        elif status_code >= 400:
            level = logging.WARNING
        
        self.logger.log(
            level,
            f"{method} {path} - {status_code} - {duration_ms:.2f}ms",
            extra={"extra_fields": extra}
        )


class AnalysisLogger:
    """Logger for analysis operations with progress tracking."""
    
    def __init__(self, logger: logging.Logger, analysis_id: str):
        self.logger = logger
        self.analysis_id = analysis_id
        self.start_time = datetime.utcnow()
    
    def log_start(self, analysis_type: str, target: str):
        """Log analysis start."""
        self.logger.info(
            f"Starting {analysis_type} analysis",
            extra={
                "extra_fields": {
                    "analysis_id": self.analysis_id,
                    "analysis_type": analysis_type,
                    "target": target,
                    "event": "analysis_start"
                }
            }
        )
    
    def log_progress(self, stage: str, progress: float, message: str):
        """Log analysis progress."""
        self.logger.info(
            message,
            extra={
                "extra_fields": {
                    "analysis_id": self.analysis_id,
                    "stage": stage,
                    "progress": progress,
                    "event": "analysis_progress"
                }
            }
        )
    
    def log_complete(self, results: Dict[str, Any]):
        """Log analysis completion."""
        duration = (datetime.utcnow() - self.start_time).total_seconds()
        self.logger.info(
            f"Analysis completed in {duration:.2f}s",
            extra={
                "extra_fields": {
                    "analysis_id": self.analysis_id,
                    "duration_seconds": duration,
                    "results_summary": results,
                    "event": "analysis_complete"
                }
            }
        )
    
    def log_error(self, error: Exception, stage: Optional[str] = None):
        """Log analysis error."""
        duration = (datetime.utcnow() - self.start_time).total_seconds()
        self.logger.error(
            f"Analysis failed: {str(error)}",
            extra={
                "extra_fields": {
                    "analysis_id": self.analysis_id,
                    "stage": stage,
                    "duration_seconds": duration,
                    "error_type": type(error).__name__,
                    "event": "analysis_error"
                }
            },
            exc_info=True
        )


class AuditLogger:
    """Logger for audit trail events."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_event(
        self,
        event_type: str,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        status: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log audit event."""
        audit_data = {
            "event_type": event_type,
            "user_id": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": details or {}
        }
        
        self.logger.info(
            f"Audit: {user_id} {action} {resource_type}/{resource_id} - {status}",
            extra={"extra_fields": audit_data}
        )


# Global logger instances
_loggers: Dict[str, logging.Logger] = {}


def init_logging(
    app_name: str = "fedramp-gap-analysis",
    level: str = "INFO",
    log_dir: Optional[str] = None,
    json_format: bool = False
):
    """
    Initialize application-wide logging.
    
    Args:
        app_name: Application name for log files
        level: Default log level
        log_dir: Directory for log files
        json_format: Use JSON format for logs
    """
    # Main application logger
    log_file = None
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        log_file = str(log_path / f"{app_name}.log")
    
    main_logger = setup_logger(
        name=app_name,
        level=level,
        log_file=log_file,
        json_format=json_format
    )
    _loggers["main"] = main_logger
    
    # Request logger
    if log_dir:
        request_log_file = str(Path(log_dir) / f"{app_name}-requests.log")
    else:
        request_log_file = None
    
    request_logger = setup_logger(
        name=f"{app_name}.requests",
        level=level,
        log_file=request_log_file,
        json_format=json_format
    )
    _loggers["requests"] = request_logger
    
    # Audit logger
    if log_dir:
        audit_log_file = str(Path(log_dir) / f"{app_name}-audit.log")
    else:
        audit_log_file = None
    
    audit_logger = setup_logger(
        name=f"{app_name}.audit",
        level="INFO",
        log_file=audit_log_file,
        json_format=True  # Always use JSON for audit logs
    )
    _loggers["audit"] = audit_logger
    
    main_logger.info(f"Logging initialized for {app_name}")


def get_main_logger() -> logging.Logger:
    """Get main application logger."""
    return _loggers.get("main", logging.getLogger())


def get_request_logger() -> RequestLogger:
    """Get request logger."""
    logger = _loggers.get("requests", logging.getLogger())
    return RequestLogger(logger)


def get_audit_logger() -> AuditLogger:
    """Get audit logger."""
    logger = _loggers.get("audit", logging.getLogger())
    return AuditLogger(logger)

# Made with Bob
