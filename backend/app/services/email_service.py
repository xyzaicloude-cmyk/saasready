import smtplib
import logging
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import HTTPException, status
from ..core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self):
        self.smtp_host = settings.EMAIL_SMTP_HOST
        self.smtp_port = settings.EMAIL_SMTP_PORT
        self.smtp_username = settings.EMAIL_SMTP_USERNAME
        self.smtp_password = settings.EMAIL_SMTP_PASSWORD
        self.use_tls = settings.EMAIL_USE_TLS
        self.use_ssl = settings.EMAIL_USE_SSL
        self.from_email = settings.EMAIL_FROM

        # Log configuration on initialization
        print("EmailService initialized with configuration:")
        print(f"SMTP Host: {self.smtp_host}")
        print(f"SMTP Port: {self.smtp_port}")
        print(f"SMTP Username: {self.smtp_username}")
        print(f"Use TLS: {self.use_tls}")
        print(f"Use SSL: {self.use_ssl}")
        print(f"From Email: {self.from_email}")

    def _send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None):
        """Internal method to send email via SMTP"""
        print(f"Attempting to send email to: {to_email}")
        print(f"Subject: {subject}")
        print(f"SMTP Host: {self.smtp_host}")
        print(f"SMTP Port: {self.smtp_port}")
        print(f"Use TLS: {self.use_tls}, Use SSL: {self.use_ssl}")

        try:
            # SMTP connection setup
            print("Establishing SMTP connection...")
            if self.use_ssl:
                print("Using SSL for SMTP connection")
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
                print("SSL SMTP connection established successfully")
            else:
                print("Using plain SMTP connection")
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                print("Plain SMTP connection established successfully")

            # TLS handling
            if self.use_tls and not self.use_ssl:
                print("Starting TLS encryption...")
                server.starttls()
                print("TLS started successfully")

            # Authentication
            if self.smtp_username and self.smtp_password:
                print("Attempting SMTP authentication...")
                logger.debug(f"Username: {self.smtp_username}")
                server.login(self.smtp_username, self.smtp_password)
                print("SMTP authentication successful")
            else:
                logger.warning("No SMTP credentials provided - attempting unauthenticated send")

            # Create message
            print("Creating email message...")
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to_email

            # Attach both HTML and plain text parts
            if text_content:
                logger.debug("Attaching plain text content")
                part1 = MIMEText(text_content, 'plain')
                msg.attach(part1)

            logger.debug("Attaching HTML content")
            part2 = MIMEText(html_content, 'html')
            msg.attach(part2)

            # Send email
            print(f"Sending email to {to_email}...")
            server.send_message(msg)
            print("Email sent successfully")

            # Cleanup
            print("Closing SMTP connection...")
            server.quit()
            print("SMTP connection closed")

            print(f"Email sent successfully to {to_email}")
            return True

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error occurred while sending email to {to_email}")
            logger.error(f"SMTP error code: {e.smtp_code if hasattr(e, 'smtp_code') else 'N/A'}")
            logger.error(f"SMTP error message: {e.smtp_error if hasattr(e, 'smtp_error') else str(e)}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"SMTP error while sending email: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Unexpected error occurred while sending email to {to_email}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error message: {str(e)}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send email: {str(e)}"
            )

    def send_invitation_email(self, to_email: str, invite_link: str, org_name: str, invited_by: str):
        """Send organization invitation email"""
        print(f"Sending invitation email to {to_email} for organization {org_name}")
        subject = f"Invitation to join {org_name} on SaaSReady"

        html_content = f"""
        <html>
            <body>
                <h2>You've been invited to join {org_name}</h2>
                <p>You've been invited by {invited_by} to join the organization <strong>{org_name}</strong> on SaaSReady.</p>
                <p>Click the link below to accept your invitation and get started:</p>
                <p><a href="{invite_link}" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Accept Invitation</a></p>
                <p>Or copy and paste this URL in your browser:<br>{invite_link}</p>
                <p>This invitation link will expire in 7 days.</p>
                <hr>
                <p><small>If you didn't expect this invitation, you can safely ignore this email.</small></p>
            </body>
        </html>
        """

        text_content = f"""
        You've been invited to join {org_name}
        
        You've been invited by {invited_by} to join the organization {org_name} on SaaSReady.
        
        Accept your invitation here: {invite_link}
        
        This invitation link will expire in 7 days.
        
        If you didn't expect this invitation, you can safely ignore this email.
        """

        return self._send_email(to_email, subject, html_content, text_content)

    def send_password_reset_email(self, to_email: str, reset_link: str):
        """Send password reset email"""
        print(f"Sending password reset email to {to_email}")
        subject = "Reset your SaaSReady password"

        html_content = f"""
        <html>
            <body>
                <h2>Reset your password</h2>
                <p>We received a request to reset your password for your SaaSReady account.</p>
                <p>Click the link below to reset your password:</p>
                <p><a href="{reset_link}" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a></p>
                <p>Or copy and paste this URL in your browser:<br>{reset_link}</p>
                <p>This password reset link will expire in 1 hour.</p>
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

        return self._send_email(to_email, subject, html_content, text_content)

    def send_verification_email(self, to_email: str, verify_link: str):
        """Send email verification email"""
        print(f"Sending verification email to {to_email}")
        subject = "Verify your email address for SaaSReady"

        html_content = f"""
        <html>
            <body>
                <h2>Verify your email address</h2>
                <p>Thank you for signing up for SaaSReady! Please verify your email address to complete your account setup.</p>
                <p>Click the link below to verify your email:</p>
                <p><a href="{verify_link}" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email</a></p>
                <p>Or copy and paste this URL in your browser:<br>{verify_link}</p>
                <p>This verification link will expire in 24 hours.</p>
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

        return self._send_email(to_email, subject, html_content, text_content)


# Global instance
email_service = EmailService()