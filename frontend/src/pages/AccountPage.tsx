import { useId, useState, type FormEvent, type ReactNode } from 'react';

import { api, toApiError, type Role } from '../api/client';
import { KeyValueList } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { formatTime, humanize } from '../lib/format';
import { useAuth, useCan, useSession } from '../lib/auth';
import { useTitle } from '../lib/useTitle';

const MIN_PASSWORD = 12;

/** Shows `children` only to accounts whose role includes `role`. */
export function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  return useCan(role) ? <>{children}</> : <NotPermitted role={role} />;
}

function NotPermitted({ role }: { role: Role }) {
  useTitle('Not permitted');
  return (
    <>
      <PageHeader title="Not permitted" />
      <p>This page needs the {role} role. Ask an administrator if you need access.</p>
    </>
  );
}

function PasswordForm() {
  const { signedIn } = useAuth();
  const session = useSession();
  const currentId = useId();
  const newId = useId();
  const confirmId = useId();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const problem =
    next.length > 0 && [...next].length < MIN_PASSWORD
      ? `Use at least ${MIN_PASSWORD} characters.`
      : confirm.length > 0 && confirm !== next
        ? 'The two new passwords differ.'
        : null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (problem || !current || !next || next !== confirm) return;
    setBusy(true);
    setMessage(null);
    try {
      const renewed = await api.changePassword(current, next);
      signedIn(renewed);
      setCurrent('');
      setNext('');
      setConfirm('');
      setMessage({ ok: true, text: 'Password changed. Your other sessions were signed out.' });
    } catch (caught) {
      setMessage({ ok: false, text: toApiError(caught).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} aria-labelledby="password-heading" noValidate>
      <h2 id="password-heading">Change password</h2>
      <p className="muted">
        12 to 256 characters; a passphrase of several words works well. Changing it signs out your other
        sessions.
      </p>
      <input type="text" name="username" autoComplete="username" value={session?.user.username ?? ''} readOnly hidden />
      <div className="field">
        <label htmlFor={currentId}>Current password</label>
        <input
          id={currentId}
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(event) => setCurrent(event.target.value)}
        />
      </div>
      <div className="field">
        <label htmlFor={newId}>New password</label>
        <input
          id={newId}
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(event) => setNext(event.target.value)}
          aria-invalid={problem ? true : undefined}
          aria-describedby={problem ? `${newId}-problem` : undefined}
        />
      </div>
      <div className="field">
        <label htmlFor={confirmId}>New password again</label>
        <input
          id={confirmId}
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
        />
      </div>
      {problem && (
        <p id={`${newId}-problem`} className="error-text">
          {problem}
        </p>
      )}
      <button type="submit" disabled={busy || Boolean(problem) || !current || !next || next !== confirm}>
        {busy ? 'Changing…' : 'Change password'}
      </button>
      <div role="status" aria-live="polite">
        {message && <span className={message.ok ? 'ok-text' : 'error-text'}>{message.text}</span>}
      </div>
    </form>
  );
}

export function AccountPage() {
  useTitle('Account');
  const session = useSession();
  if (!session) return null;
  return (
    <>
      <PageHeader title="Account" />
      <div className="columns">
        <section className="card" aria-labelledby="account-heading">
          <h2 id="account-heading">Signed in</h2>
          <KeyValueList
            items={[
              ['Username', session.user.username],
              ['Role', humanize(session.user.role)],
              ['Session ends at the latest', formatTime(session.expires_at)],
              ['Idle timeout', `${Math.round(session.idle_timeout_seconds / 60)} minutes`],
            ]}
          />
        </section>
        <PasswordForm />
      </div>
    </>
  );
}
