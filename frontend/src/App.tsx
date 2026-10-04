import { useState } from 'react';
import { createBrowserRouter, Outlet, RouterProvider, type RouteObject } from 'react-router';

import { Layout } from './components/Layout';
import { AuthProvider, RequireAuth } from './lib/auth';
import { AccountPage, RequireRole } from './pages/AccountPage';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { CapturePage } from './pages/CapturePage';
import { AuditPage } from './pages/AuditPage';
import { CapturesPage } from './pages/CapturesPage';
import { FlowDetailPage } from './pages/FlowDetailPage';
import { FlowsPage } from './pages/FlowsPage';
import { LivePage } from './pages/LivePage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { PacketDetailPage } from './pages/PacketDetailPage';
import { PacketsPage } from './pages/PacketsPage';
import { SettingsPage } from './pages/SettingsPage';
import { UsersPage } from './pages/UsersPage';

export const routes: RouteObject[] = [
  {
    element: (
      <AuthProvider>
        <Outlet />
      </AuthProvider>
    ),
    children: [
      { path: 'login', element: <LoginPage /> },
      {
        element: (
          <RequireAuth>
            <Layout />
          </RequireAuth>
        ),
        children: [
          { index: true, element: <OverviewPage /> },
          { path: 'captures', element: <CapturesPage /> },
          { path: 'captures/:id', element: <CapturePage /> },
          { path: 'captures/:id/packets', element: <PacketsPage /> },
          { path: 'captures/:id/packets/:index', element: <PacketDetailPage /> },
          { path: 'captures/:id/flows', element: <FlowsPage /> },
          { path: 'captures/:id/flows/:flowId', element: <FlowDetailPage /> },
          { path: 'captures/:id/alerts', element: <AlertsPage /> },
          { path: 'captures/:id/alerts/:alertId', element: <AlertDetailPage /> },
          { path: 'settings', element: <SettingsPage /> },
          { path: 'account', element: <AccountPage /> },
          {
            path: 'users',
            element: (
              <RequireRole role="admin">
                <UsersPage />
              </RequireRole>
            ),
          },
          {
            path: 'live',
            element: (
              <RequireRole role="admin">
                <LivePage />
              </RequireRole>
            ),
          },
          {
            path: 'audit',
            element: (
              <RequireRole role="admin">
                <AuditPage />
              </RequireRole>
            ),
          },
          { path: '*', element: <NotFoundPage /> },
        ],
      },
    ],
  },
];

export function App() {
  const [router] = useState(() => createBrowserRouter(routes));
  return <RouterProvider router={router} />;
}
