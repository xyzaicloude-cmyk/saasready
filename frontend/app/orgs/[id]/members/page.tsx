'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import ProtectedRoute from '@/components/ProtectedRoute';
import OrgSwitcher from '@/components/OrgSwitcher';
import MembersList from '@/components/MembersList';
import OrgNavTabs from '@/components/OrgNavTabs';

import { api } from '@/lib/api';
import type { Role } from '@/lib/types';

export default function MembersPage() {
  const params = useParams();
  const orgId = params.id as string;
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [roleId, setRoleId] = useState('');
  const [roles, setRoles] = useState<Role[]>([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const [loadingRoles, setLoadingRoles] = useState(false);

  useEffect(() => {
    if (showInviteForm && roles.length === 0) {
      fetchRoles();
    }
  }, [showInviteForm]);

  const fetchRoles = async () => {
    setLoadingRoles(true);
    try {
      const rolesData = await api.getRoles(orgId);
      setRoles(rolesData);
      if (rolesData.length > 0) {
        setRoleId(rolesData[0].id);
      }
    } catch (err: any) {
      setError('Failed to load roles');
    } finally {
      setLoadingRoles(false);
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      await api.inviteUser(orgId, {
        email,
        role_id: roleId,
        full_name: fullName || undefined
      });
      setSuccess('User invited successfully!');
      setEmail('');
      setFullName('');
      setRoleId(roles.length > 0 ? roles[0].id : '');
      setShowInviteForm(false);
      setRefreshKey((prev) => prev + 1);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to invite user');
    }
  };

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <div className="px-4 py-6 sm:px-0">
            <OrgSwitcher currentOrgId={orgId} />

            <div className="flex justify-between items-center mb-6">
              <h1 className="text-3xl font-bold text-gray-900">Members</h1>
              <button
                onClick={() => setShowInviteForm(!showInviteForm)}
                className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                {showInviteForm ? 'Cancel' : 'Invite Member'}
              </button>
            </div>

            {success && (
              <div className="bg-green-50 border border-green-200 rounded-md p-4 mb-6">
                <p className="text-sm text-green-800">{success}</p>
              </div>
            )}

            {showInviteForm && (
              <div className="bg-white shadow-sm rounded-lg p-6 mb-6">
                <h2 className="text-xl font-semibold mb-4">Invite New Member</h2>
                {error && (
                  <div className="bg-red-50 border border-red-200 rounded-md p-4 mb-4">
                    <p className="text-sm text-red-800">{error}</p>
                  </div>
                )}
                <form onSubmit={handleInvite} className="space-y-4">
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                      Email Address
                    </label>
                    <input
                      type="email"
                      id="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                      placeholder="user@example.com"
                    />
                  </div>
                  <div>
                    <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-1">
                      Full Name (optional)
                    </label>
                    <input
                      type="text"
                      id="fullName"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                      placeholder="John Doe"
                    />
                  </div>
                  <div>
                    <label htmlFor="roleId" className="block text-sm font-medium text-gray-700 mb-1">
                      Role
                    </label>
                    {loadingRoles ? (
                      <div className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-gray-500">
                        Loading roles...
                      </div>
                    ) : roles.length > 0 ? (
                      <select
                        id="roleId"
                        value={roleId}
                        onChange={(e) => setRoleId(e.target.value)}
                        required
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                      >
                        {roles.map((role) => (
                          <option key={role.id} value={role.id}>
                            {role.name}
                            {role.description && ` - ${role.description}`}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <div className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-gray-500">
                        No roles available
                      </div>
                    )}
                  </div>
                  <button
                    type="submit"
                    disabled={loadingRoles || roles.length === 0}
                    className="bg-primary-600 hover:bg-primary-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-4 py-2 rounded-md text-sm font-medium"
                  >
                    Send Invite
                  </button>
                </form>
              </div>
            )}

            <MembersList key={refreshKey} orgId={orgId} />
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}