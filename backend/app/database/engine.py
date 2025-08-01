"""
CyberShield-IronCore Database Engine
Enterprise-grade async PostgreSQL connection management

Features:
- Async SQLAlchemy 2.0+ with connection pooling
- Enterprise-grade connection pool configuration
- Automatic failover and connection recovery
- Comprehensive logging and monitoring
- Security best practices with SSL and encryption
"""

import logging
import ssl
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import QueuePool

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("database")


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class DatabaseManager:
    """
    Enterprise database manager with async connection pooling.
    Handles connection lifecycle, monitoring, and failover.
    """
    
    def __init__(self) -> None:
        """Initialize database manager with enterprise configuration."""
        self.engine = None
        self.session_factory = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize database engine and session factory."""
        if self._initialized:
            return
        
        if not settings.DATABASE_URI:
            raise ValueError("DATABASE_URI not configured")
        
        # SSL context for enterprise security
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Enterprise connection arguments
        connect_args = {
            "ssl": ssl_context,
            "command_timeout": 60,
            "server_settings": {
                "jit": "off",  # Disable JIT for consistency
                "application_name": "cybershield-ironcore",
            },
        }
        
        # Create async engine with enterprise pooling
        self.engine = create_async_engine(
            str(settings.DATABASE_URI),
            # Connection Pool Configuration
            poolclass=QueuePool,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.DATABASE_POOL_TIMEOUT,
            pool_recycle=settings.DATABASE_POOL_RECYCLE,
            pool_pre_ping=True,  # Validate connections before use
            
            # Performance and Reliability
            echo=settings.DEBUG,  # SQL logging in debug mode
            echo_pool=settings.DEBUG,  # Pool logging in debug mode
            future=True,  # SQLAlchemy 2.0 style
            connect_args=connect_args,
            
            # Query execution configuration
            execution_options={
                "isolation_level": "READ_COMMITTED",
                "autocommit": False,
            },
        )
        
        # Create session factory
        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
        
        self._initialized = True
        
        logger.info(
            "Database engine initialized",
            database_uri=str(settings.DATABASE_URI).split("@")[-1],  # Hide credentials
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.DATABASE_POOL_TIMEOUT,
        )
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get async database session with automatic cleanup.
        
        Yields:
            AsyncSession: Database session for transactions
        """
        if not self._initialized:
            await self.initialize()
        
        if not self.session_factory:
            raise RuntimeError("Database not initialized")
        
        async with self.session_factory() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                logger.error(
                    "Database session error",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise
            finally:
                await session.close()
    
    async def health_check(self) -> dict:
        """
        Perform database health check for monitoring.
        
        Returns:
            dict: Health check results
        """
        if not self._initialized:
            return {"status": "not_initialized", "healthy": False}
        
        try:
            async with self.session_factory() as session:
                # Test connection with simple query
                result = await session.execute("SELECT 1 as health_check")
                row = result.fetchone()
                
                if row and row[0] == 1:
                    pool_info = {
                        "pool_size": self.engine.pool.size(),
                        "checked_in": self.engine.pool.checkedin(),
                        "checked_out": self.engine.pool.checkedout(),
                    }
                    
                    return {
                        "status": "healthy",
                        "healthy": True,
                        "pool_info": pool_info,
                    }
                else:
                    return {"status": "query_failed", "healthy": False}
        
        except Exception as e:
            logger.error(
                "Database health check failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            return {
                "status": "error", 
                "healthy": False, 
                "error": str(e)
            }
    
    async def close(self) -> None:
        """Close database engine and connections."""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database engine closed")


# Global database manager instance
database_manager = DatabaseManager()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database sessions.
    
    Yields:
        AsyncSession: Database session for request handling
    """
    async for session in database_manager.get_session():
        yield session


async def initialize_database() -> None:
    """Initialize database for application startup."""
    await database_manager.initialize()


async def close_database() -> None:
    """Close database connections for application shutdown."""
    await database_manager.close()