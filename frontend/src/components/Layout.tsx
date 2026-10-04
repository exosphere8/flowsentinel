import { useState, type ReactNode } from 'react';
import { Link, NavLink, Outlet } from 'react-router';

import { roleIncludes } from '../api/client';
import { useAuth, useSession } from '../lib/auth';

function AccountMenu() {
  const session = useSession();
  const { signOut } = useAuth();
  const [busy, setBusy] = useState(false);
  if (!session) return null;
  return (
    <div className="account-menu">
      <NavLink to="/account">
        {session.user.username} <span className="muted">({session.user.role})</span>
      </NavLink>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() => {
          setBusy(true);
          signOut().catch(() => setBusy(false));
        }}
      >
        Sign out
      </button>
    </div>
  );
}

export function Layout() {
  const admin = roleIncludes(useSession()?.user.role, 'admin');
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="app-header">
        <Link to="/" className="brand">
          <img src="/favicon.svg" alt="" width={24} height={24} />
          FlowSentinel
        </Link>
        <nav aria-label="Main">
          <ul>
            <li>
              <NavLink to="/" end>
                Overview
              </NavLink>
            </li>
            <li>
              <NavLink to="/captures">Captures</NavLink>
            </li>
            <li>
              <NavLink to="/settings">Settings</NavLink>
            </li>
            {admin && (
              <>
                <li>
                  <NavLink to="/users">Users</NavLink>
                </li>
                <li>
                  <NavLink to="/audit">Audit log</NavLink>
                </li>
              </>
            )}
          </ul>
        </nav>
        <AccountMenu />
      </header>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="app-footer">
        Metadata only: packet payloads are never stored or shown. Analyze only traffic you are
        authorized to inspect.
      </footer>
    </>
  );
}

export interface Crumb {
  label: string;
  to?: string;
}

/** Page heading with breadcrumbs. */
export function PageHeader({
  title,
  crumbs = [],
  children,
}: {
  title: string;
  crumbs?: Crumb[];
  children?: ReactNode;
}) {
  return (
    <div className="page-header">
      {crumbs.length > 0 && (
        <nav aria-label="Breadcrumb">
          <ol className="crumbs">
            {crumbs.map((crumb) => (
              <li key={crumb.label}>{crumb.to ? <Link to={crumb.to}>{crumb.label}</Link> : crumb.label}</li>
            ))}
          </ol>
        </nav>
      )}
      <h1>{title}</h1>
      {children}
    </div>
  );
}

/** Links between a capture's views. */
export function CaptureTabs({ id }: { id: number }) {
  return (
    <nav aria-label="Capture views" className="tabs">
      <NavLink to={`/captures/${id}`} end>
        Summary
      </NavLink>
      <NavLink to={`/captures/${id}/packets`}>Packets</NavLink>
      <NavLink to={`/captures/${id}/flows`}>Flows</NavLink>
      <NavLink to={`/captures/${id}/alerts`}>Alerts</NavLink>
    </nav>
  );
}
