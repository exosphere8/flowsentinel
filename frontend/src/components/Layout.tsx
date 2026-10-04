import type { ReactNode } from 'react';
import { Link, NavLink, Outlet } from 'react-router';

export function Layout() {
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
          </ul>
        </nav>
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
