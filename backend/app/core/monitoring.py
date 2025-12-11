"""
Monitoring and observability utilities
"""

import time
import logging
from typing import Callable, Any
from functools import wraps
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Monitor performance of operations"""

    @staticmethod
    def timed(operation_name: str):
        """
        Decorator to time function execution

        Usage:
            @PerformanceMonitor.timed("user_registration")
            def register_user(...):
                ...
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                start = time.time()
                try:
                    result = func(*args, **kwargs)
                    duration = time.time() - start
                    logger.info(
                        f"Operation '{operation_name}' completed",
                        extra={
                            "operation": operation_name,
                            "duration": duration,
                            "status": "success"
                        }
                    )
                    return result
                except Exception as e:
                    duration = time.time() - start
                    logger.error(
                        f"Operation '{operation_name}' failed",
                        extra={
                            "operation": operation_name,
                            "duration": duration,
                            "status": "error",
                            "error": str(e)
                        }
                    )
                    raise
            return wrapper
        return decorator

    @staticmethod
    @contextmanager
    def measure(operation_name: str):
        """
        Context manager to measure execution time

        Usage:
            with PerformanceMonitor.measure("database_query"):
                db.execute(...)
        """
        start = time.time()
        try:
            yield
        finally:
            duration = time.time() - start
            logger.info(
                f"Operation '{operation_name}' took {duration:.3f}s",
                extra={"operation": operation_name, "duration": duration}
            )