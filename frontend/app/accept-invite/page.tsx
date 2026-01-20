'use client';

import { useEffect, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { authStorage } from '@/lib/auth';

function AcceptInviteContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [invitationResult, setInvitationResult] = useState<{
    invitation_valid: boolean;
    organization_name: string;
    organization_id: string;
    invited_email: string;
    requires_registration: boolean;
    user_exists?: boolean;
    message?: string;
  } | null>(null);

  useEffect(() => {
    if (!token) {
      setError('Invalid invitation link: missing token');
      setLoading(false);
      return;
    }

    const acceptInvitation = async () => {
      try {
        setLoading(true);

        // Store invitation token first
        authStorage.setInvitationToken(token);

        // Accept invitation WITHOUT requiring login (ENTERPRISE FLOW)
        const response = await api.post('/auth/accept-invitation', { token });
        setInvitationResult(response.data);

        if (!response.data.invitation_valid) {
          setError('Invalid or expired invitation');
          authStorage.removeInvitationToken();
          return;
        }

        // If user exists and invitation was activated, redirect to login
        if (response.data.user_exists) {
          // Show success message and redirect to login
          setTimeout(() => {
            authStorage.removeInvitationToken();
            router.push('/login?message=invitation_accepted');
          }, 3000);
        }

      } catch (err: any) {
        console.error('Failed to accept invitation:', err);
        authStorage.removeInvitationToken();
        const errorMessage = err.response?.data?.detail || 'Failed to accept invitation. Please try again.';
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    acceptInvitation();
  }, [token, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8 text-center">
          <div className="flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
          </div>
          <p className="text-gray-600">Processing your invitation...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
              Invitation Error
            </h2>
          </div>
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <p className="text-sm text-red-800">{error}</p>
          </div>
          <div className="flex space-x-3">
            <Link
              href="/login"
              className="flex-1 bg-primary-600 hover:bg-primary-700 text-white text-center py-2 px-4 rounded-md transition-colors"
            >
              Log in
            </Link>
            <Link
              href="/"
              className="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 text-center py-2 px-4 rounded-md transition-colors"
            >
              Go Home
            </Link>
          </div>
        </div>
      </div>
    );
  }

  if (invitationResult) {
    // User exists and invitation was activated
    if (invitationResult.user_exists) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
          <div className="max-w-md w-full space-y-8">
            <div>
              <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                Invitation Accepted!
              </h2>
              <p className="mt-2 text-center text-sm text-gray-600">
                {invitationResult.message || 'Your invitation has been accepted successfully.'}
              </p>
            </div>
            <div className="bg-green-50 border border-green-200 rounded-md p-4">
              <p className="text-sm text-green-800">
                You are now a member of <strong>{invitationResult.organization_name}</strong>.
                Redirecting you to login...
              </p>
            </div>
            <div className="text-center">
              <Link
                href="/login"
                className="bg-primary-600 hover:bg-primary-700 text-white py-2 px-4 rounded-md transition-colors"
              >
                Go to Login
              </Link>
            </div>
          </div>
        </div>
      );
    }

    // User needs to register
    if (invitationResult.requires_registration) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
          <div className="max-w-md w-full space-y-8">
            <div>
              <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                Join {invitationResult.organization_name}
              </h2>
              <p className="mt-2 text-center text-sm text-gray-600">
                You've been invited to join <strong>{invitationResult.organization_name}</strong>
              </p>
            </div>
            <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
              <p className="text-sm text-blue-800">
                Please create an account to accept this invitation.
                {invitationResult.invited_email && (
                  <> Use <strong>{invitationResult.invited_email}</strong> to register.</>
                )}
              </p>
            </div>
            <div className="flex space-x-3">
              <Link
                href={`/register?email=${encodeURIComponent(invitationResult.invited_email || '')}`}
                className="flex-1 bg-primary-600 hover:bg-primary-700 text-white text-center py-2 px-4 rounded-md transition-colors"
              >
                Create Account
              </Link>
              <Link
                href="/"
                className="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 text-center py-2 px-4 rounded-md transition-colors"
              >
                Go Home
            </Link>
            </div>
          </div>
        </div>
      );
    }
  }

  return null;
}

export default function AcceptInvitePage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8 text-center">
          <div className="flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
          </div>
          <p className="text-gray-600">Loading invitation...</p>
        </div>
      </div>
    }>
      <AcceptInviteContent />
    </Suspense>
  );
}