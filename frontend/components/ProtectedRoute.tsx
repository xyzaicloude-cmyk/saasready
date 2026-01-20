'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { authStorage } from '@/lib/auth';

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const router = useRouter();

  useEffect(() => {
    if (!authStorage.isAuthenticated()) {
      router.push('/login');
    }
  }, [router]);

  if (!authStorage.isAuthenticated()) {
    return null;
  }

  return <>{children}</>;
}