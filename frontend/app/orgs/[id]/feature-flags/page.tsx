'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import OrgNavTabs from '@/components/OrgNavTabs';
import ProtectedRoute from '@/components/ProtectedRoute';

interface FeatureFlag {
  key: string;
  name: string;
  description: string | null;
  default_enabled: boolean;
  enabled: boolean;
  overridden: boolean;
  rollout_percent: number | null;
}

export default function FeatureFlagsPage() {
  const params = useParams();
  const router = useRouter();
  const orgId = params.id as string;

  const [flags, setFlags] = useState<FeatureFlag[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState<string | null>(null);

  useEffect(() => {
    fetchFlags();
  }, [orgId]);

  const fetchFlags = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await api.get(`/orgs/${orgId}/feature-flags`);
      setFlags(response.data);
    } catch (err: any) {
      console.error('Failed to fetch feature flags:', err);
      setError(err.response?.data?.detail || 'Failed to load feature flags');
      if (err.response?.status === 401) {
        router.push('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const toggleFlag = async (flagKey: string, currentEnabled: boolean) => {
    try {
      setUpdating(flagKey);
      await api.put(`/orgs/${orgId}/feature-flags/${flagKey}`, {
        enabled: !currentEnabled,
      });
      await fetchFlags();
    } catch (err: any) {
      console.error('Failed to toggle feature flag:', err);
      alert(err.response?.data?.detail || 'Failed to update feature flag');
    } finally {
      setUpdating(null);
    }
  };

  const resetToDefault = async (flagKey: string) => {
    if (!confirm('Reset this feature flag to its default value?')) {
      return;
    }

    try {
      setUpdating(flagKey);
      await api.delete(`/orgs/${orgId}/feature-flags/${flagKey}`);
      await fetchFlags();
    } catch (err: any) {
      console.error('Failed to reset feature flag:', err);
      alert(err.response?.data?.detail || 'Failed to reset feature flag');
    } finally {
      setUpdating(null);
    }
  };

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <OrgNavTabs orgId={orgId} />

          <div className="mb-6">
            <h1 className="text-3xl font-bold text-gray-900">Feature Flags</h1>
            <p className="text-gray-600 mt-2">
              Control which features are enabled for this organization
            </p>
          </div>

          {loading ? (
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-center py-12">
                <div className="text-gray-500">Loading feature flags...</div>
              </div>
            </div>
          ) : error ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-6">
              <p className="text-red-600">{error}</p>
              <button
                onClick={fetchFlags}
                className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
              >
                Retry
              </button>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Feature
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Key
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {flags.map((flag) => (
                    <tr key={flag.key} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div>
                          <div className="text-sm font-medium text-gray-900">
                            {flag.name}
                          </div>
                          {flag.description && (
                            <div className="text-sm text-gray-500 mt-1">
                              {flag.description}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <code className="text-sm text-gray-600 bg-gray-100 px-2 py-1 rounded">
                          {flag.key}
                        </code>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center space-x-3">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={flag.enabled}
                              onChange={() => toggleFlag(flag.key, flag.enabled)}
                              disabled={updating === flag.key}
                              className="sr-only peer"
                            />
                            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                          </label>
                          <div className="text-sm">
                            {flag.enabled ? (
                              <span className="text-green-600 font-medium">
                                Enabled
                              </span>
                            ) : (
                              <span className="text-gray-500">Disabled</span>
                            )}
                            {flag.overridden ? (
                              <div className="text-xs text-blue-600 mt-1">
                                Overridden for this org
                              </div>
                            ) : (
                              <div className="text-xs text-gray-400 mt-1">
                                Using default (
                                {flag.default_enabled ? 'on' : 'off'})
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-right text-sm">
                        {flag.overridden && (
                          <button
                            onClick={() => resetToDefault(flag.key)}
                            disabled={updating === flag.key}
                            className="text-blue-600 hover:text-blue-900 disabled:text-gray-400 transition-colors"
                          >
                            Reset to Default
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {flags.length === 0 && (
                <div className="text-center py-12 text-gray-500">
                  No feature flags available
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  );
}