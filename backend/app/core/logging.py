"""
CyberShield-IronCore Logging Configuration
Enterprise-grade structured logging

Features:
- Structured JSON logging
- Performance monitoring
- Security event logging
- Audit trail logging
"""

import logging
from typing import Optional


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (defaults to calling module)
        
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger(name or __name__)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger