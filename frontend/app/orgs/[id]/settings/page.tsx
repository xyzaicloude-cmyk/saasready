'use client';

import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import ProtectedRoute from '@/components/ProtectedRoute';
import OrgSwitcher from '@/components/OrgSwitcher';

export default function SettingsPage() {
  const params = useParams();
  const orgId = params.id as string;

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <div className="px-4 py-6 sm:px-0">
            <OrgSwitcher currentOrgId={orgId} />

            <h1 className="text-3xl font-bold text-gray-900 mb-6">Organization Settings</h1>

            <div className="bg-white shadow-sm rounded-lg p-6">
              <p className="text-gray-600">
                Organization settings functionality coming soon. This would include:
              </p>
              <ul className="mt-4 space-y-2 text-sm text-gray-600 list-disc list-inside">
                <li>General organization information</li>
                <li>Billing and subscription management</li>
                <li>Security settings</li>
                <li>SSO configuration</li>
                <li>API key management</li>
                <li>Webhooks configuration</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}