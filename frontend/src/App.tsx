import { useState } from 'react';
import { createBrowserRouter, RouterProvider, type RouteObject } from 'react-router';

import { Layout } from './components/Layout';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { CapturePage } from './pages/CapturePage';
import { CapturesPage } from './pages/CapturesPage';
import { FlowDetailPage } from './pages/FlowDetailPage';
import { FlowsPage } from './pages/FlowsPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { PacketDetailPage } from './pages/PacketDetailPage';
import { PacketsPage } from './pages/PacketsPage';
import { SettingsPage } from './pages/SettingsPage';

export const routes: RouteObject[] = [
  {
    element: <Layout />,
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
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];

export function App() {
  const [router] = useState(() => createBrowserRouter(routes));
  return <RouterProvider router={router} />;
}
