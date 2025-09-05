import sys
from loguru import logger
from src.core.config import config


def setup_logging():
    """Setup logging configuration"""
    # Remove default logger
    logger.remove()
    
    # Add console logger
    logger.add(
        sys.stderr,
        level=config.logging.level,
        format=config.logging.format,
        colorize=True
    )
    
    # Add file logger
    logger.add(
        config.logging.file,
        level=config.logging.level,
        format=config.logging.format,
        rotation=config.logging.max_size,
        retention=config.logging.backup_count,
        compression="zip"
    )
    
    return logger


# Initialize logger
setup_logging()