'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface OrgNavTabsProps {
  orgId: string;
}

export default function OrgNavTabs({ orgId }: OrgNavTabsProps) {
  const pathname = usePathname();

  const tabs = [
    { name: 'Overview', href: `/orgs/${orgId}` },
    { name: 'Members', href: `/orgs/${orgId}/members` },
    { name: 'Feature Flags', href: `/orgs/${orgId}/feature-flags` },
    { name: 'Audit Logs', href: `/orgs/${orgId}/audit-logs` },
    { name: 'Settings', href: `/orgs/${orgId}/settings` },
  ];

  return (
    <div className="border-b border-gray-200 mb-6">
      <nav className="-mb-px flex space-x-8" aria-label="Tabs">
        {tabs.map((tab) => {
          const isActive = pathname === tab.href;
          return (
            <Link
              key={tab.name}
              href={tab.href}
              className={`
                whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm
                ${
                  isActive
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }
              `}
            >
              {tab.name}
            </Link>
          );
        })}
      </nav>
    </div>
  );
}