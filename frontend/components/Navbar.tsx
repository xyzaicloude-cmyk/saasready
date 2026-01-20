'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { authStorage } from '@/lib/auth';

export default function Navbar() {
  const router = useRouter();

  const handleLogout = () => {
    authStorage.removeToken();
    router.push('/login');
  };

  return (
    <nav className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex">
            <Link href="/orgs" className="flex items-center">
              <span className="text-2xl font-bold text-primary-600">SaaSReady</span>
            </Link>
          </div>
          <div className="flex items-center space-x-4">
            <Link
              href="/orgs"
              className="text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md text-sm font-medium"
            >
              Organizations
            </Link>
            <Link
              href="/feature-flags"
              className="text-gray-700 hover:text-primary-600 px-3 py-2 rounded-md text-sm font-medium"
            >
              Feature Flags
            </Link>
            <button
              onClick={handleLogout}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}