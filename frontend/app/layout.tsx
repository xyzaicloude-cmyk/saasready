import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SaaSReady - Enterprise SaaS Starter',
  description: 'Production-ready SaaS starter kit with multi-tenancy and RBAC',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}