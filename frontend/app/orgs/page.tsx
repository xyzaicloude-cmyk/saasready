'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import Navbar from '@/components/Navbar';
import ProtectedRoute from '@/components/ProtectedRoute';
import OrgSwitcher from '@/components/OrgSwitcher';
import { api } from '@/lib/api';
import type { Organization } from '@/lib/types';

export default function OrganizationDetailPage() {
  const params = useParams();
  const router = useRouter();
  const orgId = params.id as string;
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadOrganization();
  }, [orgId]);

  const loadOrganization = async () => {
    try {
      setError(null);
      const orgs = await api.getOrganizations();
      const org = orgs.find((o) => o.id === orgId);
      if (org) {
        setOrganization(org);
      } else {
        setError('Organization not found');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load organization');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <ProtectedRoute>
        <div className="min-h-screen bg-gray-50">
          <Navbar />
          <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <div className="flex justify-center items-center py-12">
              <div className="text-gray-500">Loading...</div>
            </div>
          </div>
        </div>
      </ProtectedRoute>
    );
  }

  if (error || !organization) {
    return (
      <ProtectedRoute>
        <div className="min-h-screen bg-gray-50">
          <Navbar />
          <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <div className="px-4 py-6 sm:px-0">
              <OrgSwitcher currentOrgId={orgId} />
              <div className="bg-red-50 border border-red-200 rounded-md p-4">
                <p className="text-red-800">{error || 'Organization not found'}</p>
              </div>
            </div>
          </div>
        </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <div className="px-4 py-6 sm:px-0">
            <OrgSwitcher currentOrgId={orgId} />

            <div className="bg-white shadow-sm rounded-lg p-6 mb-6">
              <h1 className="text-3xl font-bold text-gray-900 mb-2">{organization.name}</h1>
              <p className="text-gray-500 mb-4">@{organization.slug}</p>
              {organization.description && (
                <p className="text-gray-600">{organization.description}</p>
              )}
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Link
                href={`/orgs/${orgId}/members`}
                className="bg-white shadow-sm rounded-lg p-6 hover:shadow-md transition-shadow border border-gray-200"
              >
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Members</h3>
                <p className="text-sm text-gray-600">Manage organization members and roles</p>
              </Link>

              <Link
                href={`/orgs/${orgId}/audit-logs`}
                className="bg-white shadow-sm rounded-lg p-6 hover:shadow-md transition-shadow border border-gray-200"
              >
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Audit Logs</h3>
                <p className="text-sm text-gray-600">View organization activity history</p>
              </Link>

              <Link
                href={`/orgs/${orgId}/settings`}
                className="bg-white shadow-sm rounded-lg p-6 hover:shadow-md transition-shadow border border-gray-200"
              >
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Settings</h3>
                <p className="text-sm text-gray-600">Configure organization settings</p>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}