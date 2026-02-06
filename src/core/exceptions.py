"""
Custom exceptions for FedRamp Gap Analysis Agent.

This module defines all custom exceptions used throughout the application.
"""

from typing import Any, Optional, Dict


class FedRampException(Exception):
    """Base exception for all FedRamp Gap Analysis Agent errors."""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code or "FEDRAMP_ERROR"
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details
        }


# Configuration Exceptions
class ConfigurationError(FedRampException):
    """Raised when there's a configuration error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFIG_ERROR", details)


# Authentication & Authorization Exceptions
class AuthenticationError(FedRampException):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AUTH_ERROR", details)


class AuthorizationError(FedRampException):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AUTHZ_ERROR", details)


class InvalidTokenError(AuthenticationError):
    """Raised when token is invalid or expired."""
    
    def __init__(self, message: str = "Invalid or expired token", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)


# Parsing Exceptions
class ParsingError(FedRampException):
    """Base exception for parsing errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "PARSING_ERROR", details)


class PDFParsingError(ParsingError):
    """Raised when PDF parsing fails."""
    
    def __init__(self, message: str, file_path: Optional[str] = None):
        details = {"file_path": file_path} if file_path else {}
        super().__init__(f"PDF parsing failed: {message}", details)


class DOCXParsingError(ParsingError):
    """Raised when DOCX parsing fails."""
    
    def __init__(self, message: str, file_path: Optional[str] = None):
        details = {"file_path": file_path} if file_path else {}
        super().__init__(f"DOCX parsing failed: {message}", details)


class ConfluenceParsingError(ParsingError):
    """Raised when Confluence content parsing fails."""
    
    def __init__(self, message: str, page_id: Optional[str] = None):
        details = {"page_id": page_id} if page_id else {}
        super().__init__(f"Confluence parsing failed: {message}", details)


# Analysis Exceptions
class AnalysisError(FedRampException):
    """Base exception for analysis errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "ANALYSIS_ERROR", details)


class CodeAnalysisError(AnalysisError):
    """Raised when code analysis fails."""
    
    def __init__(self, message: str, file_path: Optional[str] = None):
        details = {"file_path": file_path} if file_path else {}
        super().__init__(f"Code analysis failed: {message}", details)


class GitOperationError(AnalysisError):
    """Raised when Git operations fail."""
    
    def __init__(self, message: str, repo_url: Optional[str] = None):
        details = {"repo_url": repo_url} if repo_url else {}
        super().__init__(f"Git operation failed: {message}", details)


class DependencyAnalysisError(AnalysisError):
    """Raised when dependency analysis fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Dependency analysis failed: {message}", details)


# Gap Detection Exceptions
class GapDetectionError(FedRampException):
    """Raised when gap detection fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "GAP_DETECTION_ERROR", details)


class ControlMappingError(GapDetectionError):
    """Raised when control mapping fails."""
    
    def __init__(self, message: str, control_id: Optional[str] = None):
        details = {"control_id": control_id} if control_id else {}
        super().__init__(f"Control mapping failed: {message}", details)


class PatternMatchingError(GapDetectionError):
    """Raised when pattern matching fails."""
    
    def __init__(self, message: str, pattern: Optional[str] = None):
        details = {"pattern": pattern} if pattern else {}
        super().__init__(f"Pattern matching failed: {message}", details)


# Report Generation Exceptions
class ReportGenerationError(FedRampException):
    """Raised when report generation fails."""
    
    def __init__(self, message: str, report_format: Optional[str] = None):
        details = {"report_format": report_format} if report_format else {}
        super().__init__(message, "REPORT_ERROR", details)


class TemplateError(ReportGenerationError):
    """Raised when template rendering fails."""
    
    def __init__(self, message: str, template_name: Optional[str] = None):
        details = {"template_name": template_name} if template_name else {}
        super().__init__(f"Template error: {message}", details)


# Integration Exceptions
class IntegrationError(FedRampException):
    """Base exception for integration errors."""
    
    def __init__(self, message: str, service: Optional[str] = None):
        details = {"service": service} if service else {}
        super().__init__(message, "INTEGRATION_ERROR", details)


class WatsonXError(IntegrationError):
    """Raised when watsonx.ai integration fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"watsonx.ai error: {message}", "watsonx")
        self.details.update(details or {})


class ConfluenceAPIError(IntegrationError):
    """Raised when Confluence API calls fail."""
    
    def __init__(self, message: str, status_code: Optional[int] = None):
        details = {"status_code": status_code} if status_code else {}
        super().__init__(f"Confluence API error: {message}", "confluence")
        self.details.update(details)


class JiraAPIError(IntegrationError):
    """Raised when Jira API calls fail."""
    
    def __init__(self, message: str, status_code: Optional[int] = None):
        details = {"status_code": status_code} if status_code else {}
        super().__init__(f"Jira API error: {message}", "jira")
        self.details.update(details)


# Database Exceptions
class DatabaseError(FedRampException):
    """Raised when database operations fail."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "DATABASE_ERROR", details)


class RecordNotFoundError(DatabaseError):
    """Raised when a database record is not found."""
    
    def __init__(self, model: str, identifier: Any):
        message = f"{model} with identifier '{identifier}' not found"
        super().__init__(message, {"model": model, "identifier": str(identifier)})


class DuplicateRecordError(DatabaseError):
    """Raised when attempting to create a duplicate record."""
    
    def __init__(self, model: str, field: str, value: Any):
        message = f"{model} with {field}='{value}' already exists"
        super().__init__(message, {"model": model, "field": field, "value": str(value)})


# Cache Exceptions
class CacheError(FedRampException):
    """Raised when cache operations fail."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CACHE_ERROR", details)


# Validation Exceptions
class ValidationError(FedRampException):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[Any] = None):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        super().__init__(message, "VALIDATION_ERROR", details)


class FileValidationError(ValidationError):
    """Raised when file validation fails."""
    
    def __init__(self, message: str, file_path: Optional[str] = None):
        super().__init__(message, "file_path", file_path)


# Rate Limiting Exceptions
class RateLimitExceededError(FedRampException):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        details = {"retry_after": retry_after} if retry_after else {}
        super().__init__(message, "RATE_LIMIT_ERROR", details)


# Resource Exceptions
class ResourceError(FedRampException):
    """Base exception for resource-related errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "RESOURCE_ERROR", details)


class ResourceNotFoundError(ResourceError):
    """Raised when a resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} '{resource_id}' not found"
        super().__init__(message, {"resource_type": resource_type, "resource_id": resource_id})


class ResourceExhaustedError(ResourceError):
    """Raised when system resources are exhausted."""
    
    def __init__(self, message: str = "System resources exhausted"):
        super().__init__(message)


# Timeout Exceptions
class TimeoutError(FedRampException):
    """Raised when an operation times out."""
    
    def __init__(self, operation: str, timeout: int):
        message = f"Operation '{operation}' timed out after {timeout} seconds"
        super().__init__(message, "TIMEOUT_ERROR", {"operation": operation, "timeout": timeout})

# Made with Bob
