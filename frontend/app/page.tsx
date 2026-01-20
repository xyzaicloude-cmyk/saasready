'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { authStorage } from '@/lib/auth';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    if (authStorage.isAuthenticated()) {
      router.push('/orgs');
    } else {
      router.push('/login');
    }
  }, [router]);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-gray-500">Loading...</div>
    </div>
  );
}