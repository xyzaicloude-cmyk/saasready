import smtplib
import logging
import traceback
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import HTTPException, status
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from sqlalchemy.orm import Session
import uuid
from enum import Enum

from ..core.config import settings
from ..core.database import Base

logger = logging.getLogger(__name__)


class EmailStatus(str, Enum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    RETRY = "retry"


class EmailQueue(Base):
    """Email queue for async processing with retry"""
    __tablename__ = "email_queue"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    to_email = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    html_content = Column(Text, nullable=False)
    text_content = Column(Text, nullable=True)
    status = Column(String, default=EmailStatus.PENDING, nullable=False, index=True)
    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    error_message = Column(Text, nullable=True)
    metadata_email = Column(JSON, nullable=True)  # Template name, user_id, etc.
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    sent_at = Column(DateTime, nullable=True)
    next_retry_at = Column(DateTime, nullable=True)


class EmailService:
    """
    Enterprise-grade email service with async processing and retry mechanism
    """
    def __init__(self):
        self.smtp_host = settings.EMAIL_SMTP_HOST
        self.smtp_port = settings.EMAIL_SMTP_PORT
        self.smtp_username = settings.EMAIL_SMTP_USERNAME
        self.smtp_password = settings.EMAIL_SMTP_PASSWORD
        self.use_tls = settings.EMAIL_USE_TLS
        self.use_ssl = settings.EMAIL_USE_SSL
        self.from_email = settings.EMAIL_FROM

        # Retry configuration
        self.retry_delays = [60, 300, 3600]  # 1min, 5min, 1hour

        # Log configuration on initialization
        print("EmailService (Enterprise Async) initialized with configuration:")
        print(f"SMTP Host: {self.smtp_host}")
        print(f"SMTP Port: {self.smtp_port}")
        print(f"SMTP Username: {self.smtp_username}")
        print(f"Use TLS: {self.use_tls}")
        print(f"Use SSL: {self.use_ssl}")
        print(f"From Email: {self.from_email}")

    async def send_email(
            self,
            to_email: str,
            subject: str,
            html_content: str,
            text_content: Optional[str] = None,
            metadata_email: Optional[dict] = None,
            db: Optional[Session] = None
    ) -> str:
        """
        Queue email for async sending

        Returns:
            str: Email queue ID
        """
        if db is None:
            from ..core.database import SessionLocal
            db = SessionLocal()
            close_db = True
        else:
            close_db = False

        try:
            # Create email queue entry
            email_entry = EmailQueue(
                to_email=to_email,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                metadata=metadata_email or {}
            )

            db.add(email_entry)
            db.commit()
            db.refresh(email_entry)

            logger.info(f"📧 Email queued: {email_entry.id} to {to_email}")

            # Start async processing in background
            asyncio.create_task(self._process_email(email_entry.id))

            return email_entry.id

        finally:
            if close_db:
                db.close()

    async def _process_email(self, email_id: str):
        """Process a single email from queue"""
        from ..core.database import SessionLocal
        db = SessionLocal()

        try:
            email_entry = db.query(EmailQueue).filter(
                EmailQueue.id == email_id
            ).first()

            if not email_entry or email_entry.status not in [EmailStatus.PENDING, EmailStatus.RETRY]:
                return

            # Update status to sending
            email_entry.status = EmailStatus.SENDING
            email_entry.attempts += 1
            db.commit()

            # Send email
            try:
                await self._send_smtp_email(
                    email_entry.to_email,
                    email_entry.subject,
                    email_entry.html_content,
                    email_entry.text_content
                )

                # Mark as sent
                email_entry.status = EmailStatus.SENT
                email_entry.sent_at = datetime.utcnow()
                db.commit()

                logger.info(f"✅ Email sent successfully: {email_id}")

            except Exception as e:
                logger.error(f"❌ Email send failed: {email_id} - {str(e)}")

                # Check if should retry
                if email_entry.attempts < email_entry.max_attempts:
                    # Schedule retry
                    delay_seconds = self.retry_delays[email_entry.attempts - 1]
                    email_entry.status = EmailStatus.RETRY
                    email_entry.next_retry_at = datetime.utcnow() + timedelta(seconds=delay_seconds)
                    email_entry.error_message = str(e)
                    db.commit()

                    logger.info(
                        f"📧 Email retry scheduled: {email_id} "
                        f"(attempt {email_entry.attempts}/{email_entry.max_attempts}) "
                        f"in {delay_seconds}s"
                    )

                    # Schedule retry
                    await asyncio.sleep(delay_seconds)
                    await self._process_email(email_id)
                else:
                    # Max attempts reached
                    email_entry.status = EmailStatus.FAILED
                    email_entry.error_message = str(e)
                    db.commit()

                    logger.error(
                        f"❌ Email failed permanently: {email_id} "
                        f"after {email_entry.attempts} attempts"
                    )

        finally:
            db.close()

    async def _send_smtp_email(
            self,
            to_email: str,
            subject: str,
            html_content: str,
            text_content: Optional[str] = None
    ):
        """Send email via SMTP (blocking operation in thread pool)"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self._send_smtp_sync,
            to_email,
            subject,
            html_content,
            text_content
        )

    def _send_smtp_sync(
            self,
            to_email: str,
            subject: str,
            html_content: str,
            text_content: Optional[str] = None
    ):
        """Synchronous SMTP send for async operations"""
        try:
            # Connect to SMTP server
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)

            if self.use_tls and not self.use_ssl:
                server.starttls()

            # Login
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to_email

            if text_content:
                part1 = MIMEText(text_content, 'plain')
                msg.attach(part1)

            part2 = MIMEText(html_content, 'html')
            msg.attach(part2)

            # Send
            server.send_message(msg)
            server.quit()

        except Exception as e:
            logger.error(f"SMTP error: {e}")
            raise

    # 🎯 ENTERPRISE: Async template methods
    async def send_invitation_email(
            self,
            to_email: str,
            invite_link: str,
            org_name: str,
            invited_by: str,
            db: Optional[Session] = None
    ) -> str:
        """Send organization invitation email (Enterprise async)"""
        print(f"📧 Queuing invitation email to {to_email} for organization {org_name}")
        subject = f"Invitation to join {org_name} on SaaSReady"

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2 style="color: #333;">You've been invited to join {org_name}</h2>
                <p>You've been invited by <strong>{invited_by}</strong> to join <strong>{org_name}</strong> on SaaSReady.</p>
                <p>
                    <a href="{invite_link}" 
                       style="background-color: #4F46E5; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 4px; display: inline-block;">
                        Accept Invitation
                    </a>
                </p>
                <p style="color: #666;">This invitation expires in 7 days.</p>
                <hr>
                <p><small>If you didn't expect this invitation, you can safely ignore this email.</small></p>
            </body>
        </html>
        """

        text_content = f"""
        You've been invited to join {org_name}
        
        Invited by: {invited_by}
        
        Accept invitation: {invite_link}
        
        This invitation expires in 7 days.
        
        If you didn't expect this invitation, you can safely ignore this email.
        """

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            metadata_email={"template": "invitation", "org_name": org_name},
            db=db
        )

    async def send_password_reset_email(
            self,
            to_email: str,
            reset_link: str,
            db: Optional[Session] = None
    ) -> str:
        """Send password reset email (Enterprise async)"""
        print(f"📧 Queuing password reset email to {to_email}")
        subject = "Reset your SaaSReady password"

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2 style="color: #333;">Reset your password</h2>
                <p>We received a request to reset your password for your SaaSReady account.</p>
                <p>
                    <a href="{reset_link}" 
                       style="background-color: #4F46E5; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 4px; display: inline-block;">
                        Reset Password
                    </a>
                </p>
                <p style="color: #666;">This password reset link will expire in 1 hour.</p>
                <hr>
                <p><small>If you didn't request a password reset, you can safely ignore this email.</small></p>
            </body>
        </html>
        """

        text_content = f"""
        Reset your password
        
        We received a request to reset your password for your SaaSReady account.
        
        Reset your password here: {reset_link}
        
        This password reset link will expire in 1 hour.
        
        If you didn't request a password reset, you can safely ignore this email.
        """

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            metadata_email={"template": "password_reset"}
        )

    async def send_verification_email(
            self,
            to_email: str,
            verify_link: str,
            db: Optional[Session] = None
    ) -> str:
        """Send email verification email (Enterprise async)"""
        print(f"📧 Queuing verification email to {to_email}")
        subject = "Verify your email address for SaaSReady"

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2 style="color: #333;">Verify your email address</h2>
                <p>Thank you for signing up for SaaSReady! Please verify your email address to complete your account setup.</p>
                <p>
                    <a href="{verify_link}" 
                       style="background-color: #4F46E5; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 4px; display: inline-block;">
                        Verify Email
                    </a>
                </p>
                <p style="color: #666;">This verification link will expire in 24 hours.</p>
                <hr>
                <p><small>If you didn't create a SaaSReady account, you can safely ignore this email.</small></p>
            </body>
        </html>
        """

        text_content = f"""
        Verify your email address
        
        Thank you for signing up for SaaSReady! Please verify your email address to complete your account setup.
        
        Verify your email here: {verify_link}
        
        This verification link will expire in 24 hours.
        
        If you didn't create a SaaSReady account, you can safely ignore this email.
        """

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            metadata_email={"template": "verification"},
            db=db
        )

    # 🎯 ENTERPRISE: Background task methods
    async def process_retry_queue(self, db: Session):
        """Process emails scheduled for retry"""
        emails = db.query(EmailQueue).filter(
            EmailQueue.status == EmailStatus.RETRY,
            EmailQueue.next_retry_at <= datetime.utcnow()
        ).limit(100).all()

        for email in emails:
            await self._process_email(email.id)

    def cleanup_old_emails(self, db: Session, days: int = 30):
        """Cleanup old sent/failed emails"""
        cutoff = datetime.utcnow() - timedelta(days=days)

        deleted = db.query(EmailQueue).filter(
            EmailQueue.status.in_([EmailStatus.SENT, EmailStatus.FAILED]),
            EmailQueue.created_at < cutoff
        ).delete()

        db.commit()
        logger.info(f"Cleaned up {deleted} old emails")

        return deleted


# Global instance (enterprise-grade async)
email_service = EmailService()