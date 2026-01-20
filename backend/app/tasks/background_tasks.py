# backend/app/tasks/background_tasks.py
"""
Background tasks for cleanup and maintenance
Run these as cron jobs or using APScheduler
"""
import asyncio
import logging
from datetime import datetime, timedelta,timezone
from sqlalchemy.orm import Session

from ..core.database import SessionLocal
from ..core.config import settings
from ..core.security import cleanup_expired_tokens
from ..services.email_service import email_service
from ..models.token_blacklist import TokenBlacklist, UserSession
from ..services.brute_force_protection import BruteForceProtection

logger = logging.getLogger(__name__)


class BackgroundTaskRunner:
    """
    Background task runner for maintenance jobs
    """

    def __init__(self):
        self.running = False

    async def start(self):
        """Start all background tasks"""
        self.running = True
        logger.info("🚀 Starting background tasks...")

        # Run tasks concurrently
        await asyncio.gather(
            self.cleanup_expired_tokens_task(),
            self.cleanup_old_sessions_task(),
            self.process_email_retry_queue_task(),
            self.cleanup_old_emails_task(),
            self.cleanup_old_login_attempts_task()
        )

    async def stop(self):
        """Stop all background tasks"""
        self.running = False
        logger.info("🛑 Stopping background tasks...")

    async def cleanup_expired_tokens_task(self):
        """Cleanup expired JWT tokens from blacklist"""
        while self.running:
            try:
                db = SessionLocal()
                try:
                    cleanup_expired_tokens(db)
                    logger.info("✅ Cleaned up expired tokens")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"❌ Error cleaning up tokens: {e}")

            # Run every hour
            await asyncio.sleep(settings.CLEANUP_EXPIRED_TOKENS_INTERVAL)

    async def cleanup_old_sessions_task(self):
        """Cleanup old inactive sessions"""
        while self.running:
            try:
                db = SessionLocal()
                try:
                    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
                    deleted = db.query(UserSession).filter(
                        UserSession.is_active == False,
                        UserSession.created_at < cutoff
                    ).delete()
                    db.commit()

                    if deleted > 0:
                        logger.info(f"✅ Cleaned up {deleted} old sessions")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"❌ Error cleaning up sessions: {e}")

            # Run every hour
            await asyncio.sleep(3600)

    async def process_email_retry_queue_task(self):
        """Process emails scheduled for retry"""
        while self.running:
            try:
                db = SessionLocal()
                try:
                    await email_service.process_retry_queue(db)
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"❌ Error processing email retry queue: {e}")

            # Run every 5 minutes
            await asyncio.sleep(300)

    async def cleanup_old_emails_task(self):
        """Cleanup old sent/failed emails"""
        while self.running:
            try:
                db = SessionLocal()
                try:
                    email_service.cleanup_old_emails(
                        db,
                        days=settings.CLEANUP_OLD_EMAILS_DAYS
                    )
                    logger.info("✅ Cleaned up old emails")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"❌ Error cleaning up old emails: {e}")

            # Run daily
            await asyncio.sleep(86400)

    async def cleanup_old_login_attempts_task(self):
        """Cleanup old login attempts"""
        while self.running:
            try:
                db = SessionLocal()
                try:
                    bf_protection = BruteForceProtection(db)
                    bf_protection.cleanup_old_attempts(days=30)
                    logger.info("✅ Cleaned up old login attempts")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"❌ Error cleaning up login attempts: {e}")

            # Run daily
            await asyncio.sleep(86400)


# Global task runner instance
task_runner = BackgroundTaskRunner()


async def start_background_tasks():
    """Start background tasks (call on app startup)"""
    await task_runner.start()


async def stop_background_tasks():
    """Stop background tasks (call on app shutdown)"""
    await task_runner.stop()


# Standalone script for running as cron jobs
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python background_tasks.py <task_name>")
        print("Available tasks:")
        print("  - cleanup_tokens")
        print("  - cleanup_sessions")
        print("  - process_email_retry")
        print("  - cleanup_emails")
        print("  - cleanup_login_attempts")
        sys.exit(1)

    task_name = sys.argv[1]
    db = SessionLocal()

    try:
        if task_name == "cleanup_tokens":
            cleanup_expired_tokens(db)
            print("✅ Cleaned up expired tokens")

        elif task_name == "cleanup_sessions":
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            deleted = db.query(UserSession).filter(
                UserSession.is_active == False,
                UserSession.created_at < cutoff
            ).delete()
            db.commit()
            print(f"✅ Cleaned up {deleted} old sessions")

        elif task_name == "process_email_retry":
            asyncio.run(email_service.process_retry_queue(db))
            print("✅ Processed email retry queue")

        elif task_name == "cleanup_emails":
            email_service.cleanup_old_emails(db, days=settings.CLEANUP_OLD_EMAILS_DAYS)
            print("✅ Cleaned up old emails")

        elif task_name == "cleanup_login_attempts":
            bf_protection = BruteForceProtection(db)
            bf_protection.cleanup_old_attempts(days=30)
            print("✅ Cleaned up old login attempts")

        else:
            print(f"❌ Unknown task: {task_name}")
            sys.exit(1)

    except Exception as e:
        print(f"❌ Error running task {task_name}: {e}")
        sys.exit(1)

    finally:
        db.close()