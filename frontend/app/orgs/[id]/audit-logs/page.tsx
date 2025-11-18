'use client';

import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import ProtectedRoute from '@/components/ProtectedRoute';
import OrgSwitcher from '@/components/OrgSwitcher';
import AuditLogTable from '@/components/AuditLogTable';

export default function AuditLogsPage() {
  const params = useParams();
  const orgId = params.id as string;

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <div className="px-4 py-6 sm:px-0">
            <OrgSwitcher currentOrgId={orgId} />

            <h1 className="text-3xl font-bold text-gray-900 mb-6">Audit Logs</h1>

            <AuditLogTable orgId={orgId} />
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}