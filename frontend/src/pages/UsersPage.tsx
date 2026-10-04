import { useId, useState, type FormEvent } from 'react';

import { api, ROLES, toApiError, type Role, type User } from '../api/client';
import { TableScroll } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { Pagination, PastEnd } from '../components/Pagination';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatTime } from '../lib/format';
import { useSession } from '../lib/auth';
import { useResource } from '../lib/useResource';
import { useSearchState } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';

const PER_PAGE = 50;

const ROLE_HELP: Record<Role, string> = {
  viewer: 'reads captures, packets, flows, alerts and settings',
  analyst: 'also imports captures and triages alerts',
  admin: 'also deletes captures, changes settings, manages accounts and reads the audit log',
};

function CreateForm({ onCreated }: { onCreated: () => void }) {
  const nameId = useId();
  const passwordId = useId();
  const roleId = useId();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const user = await api.createUser(username, password, role);
      setUsername('');
      setPassword('');
      setMessage({ ok: true, text: `Created ${user.username} (${user.role}).` });
      onCreated();
    } catch (caught) {
      setMessage({ ok: false, text: toApiError(caught).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} aria-labelledby="create-heading">
      <h2 id="create-heading">Create an account</h2>
      <div className="field">
        <label htmlFor={nameId}>Username</label>
        <input
          id={nameId}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={64}
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />
      </div>
      <div className="field">
        <label htmlFor={passwordId}>Initial password</label>
        <input
          id={passwordId}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-describedby={`${passwordId}-help`}
        />
        <span id={`${passwordId}-help`} className="muted">
          12 to 256 characters, not containing the username. Share it privately; the user can change it.
        </span>
      </div>
      <div className="field">
        <label htmlFor={roleId}>Role</label>
        <select id={roleId} value={role} onChange={(event) => setRole(event.target.value as Role)}>
          {ROLES.map((value) => (
            <option key={value} value={value}>
              {value}: {ROLE_HELP[value]}
            </option>
          ))}
        </select>
      </div>
      <button type="submit" disabled={busy || !username || !password}>
        {busy ? 'Creating…' : 'Create account'}
      </button>
      <div role="status" aria-live="polite">
        {message && <span className={message.ok ? 'ok-text' : 'error-text'}>{message.text}</span>}
      </div>
    </form>
  );
}

function UserRow({ user, self, onChanged }: { user: User; self: boolean; onChanged: () => void }) {
  const roleId = useId();
  const passwordId = useId();
  const [role, setRole] = useState<Role>(user.role);
  const [resetting, setResetting] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function run(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      setMessage({ ok: true, text: done });
      setResetting(false);
      setPassword('');
      onChanged();
    } catch (caught) {
      setMessage({ ok: false, text: toApiError(caught).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr>
      <th scope="row">
        {user.username}
        {self && <span className="muted"> (you)</span>}
      </th>
      <td>
        <label htmlFor={roleId} className="sr-only">
          Role of {user.username}
        </label>
        <select id={roleId} value={role} onChange={(event) => setRole(event.target.value as Role)} disabled={busy}>
          {ROLES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        {role !== user.role && (
          <button
            type="button"
            onClick={() => run(() => api.updateUser(user.id, { role }), `Role changed to ${role}.`)}
            disabled={busy}
          >
            Save role
          </button>
        )}
      </td>
      <td>{user.disabled ? 'Disabled' : 'Enabled'}</td>
      <td>{formatTime(user.last_login_at)}</td>
      <td className="actions">
        <button
          type="button"
          className="secondary"
          aria-label={`${user.disabled ? 'Enable' : 'Disable'} ${user.username}`}
          onClick={() =>
            run(
              () => api.updateUser(user.id, { disabled: !user.disabled }),
              user.disabled ? 'Enabled.' : 'Disabled; its sessions ended.',
            )
          }
          disabled={busy}
        >
          {user.disabled ? 'Enable' : 'Disable'}
        </button>
        {resetting ? (
          <span className="confirm">
            <label htmlFor={passwordId} className="sr-only">
              New password for {user.username}
            </label>
            <input
              id={passwordId}
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <button
              type="button"
              onClick={() => run(() => api.updateUser(user.id, { password }), 'Password set; its sessions ended.')}
              disabled={busy || !password}
            >
              Set password
            </button>
            <button type="button" className="secondary" onClick={() => setResetting(false)}>
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            className="secondary"
            aria-label={`Reset the password of ${user.username}`}
            onClick={() => setResetting(true)}
            disabled={busy}
          >
            Reset password
          </button>
        )}
        {!self &&
          (confirmingDelete ? (
            <span className="confirm">
              <button
                type="button"
                className="danger"
                aria-label={`Confirm delete ${user.username}`}
                onClick={() => run(() => api.deleteUser(user.id), 'Deleted.')}
                disabled={busy}
              >
                Confirm delete
              </button>
              <button type="button" className="secondary" onClick={() => setConfirmingDelete(false)}>
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              className="secondary"
              aria-label={`Delete ${user.username}`}
              onClick={() => setConfirmingDelete(true)}
              disabled={busy}
            >
              Delete
            </button>
          ))}
        <span role="status" aria-live="polite">
          {message && <span className={message.ok ? 'ok-text' : 'error-text'}>{message.text}</span>}
        </span>
      </td>
    </tr>
  );
}

export function UsersPage() {
  useTitle('Users');
  const session = useSession();
  const search = useSearchState();
  const page = search.number('page', 1);
  const users = useResource(`users:${page}`, (signal) => api.listUsers({ page, per_page: PER_PAGE }, signal));
  const shown = users.data ?? users.previous;

  return (
    <>
      <PageHeader title="Users">
        <p className="lead">
          Viewers read; analysts also import captures and triage alerts; admins also delete captures, change
          settings, manage accounts and read the audit log. Changing an account's role, enabling or disabling
          it, or setting its password signs it out everywhere.
        </p>
      </PageHeader>
      <CreateForm onCreated={users.reload} />
      <section aria-labelledby="accounts-heading">
        <h2 id="accounts-heading">Accounts</h2>
        {users.error ? (
          <ErrorState error={users.error} onRetry={users.reload} />
        ) : !shown ? (
          <Loading />
        ) : shown.items.length === 0 && shown.total > 0 ? (
          <PastEnd total={shown.total} perPage={PER_PAGE} onPage={(next) => search.update({ page: next })} />
        ) : shown.total === 0 ? (
          <EmptyState title="No accounts" />
        ) : (
          <div aria-busy={users.loading}>
            <TableScroll label="Accounts">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Username</th>
                    <th scope="col">Role</th>
                    <th scope="col">State</th>
                    <th scope="col">Last sign-in</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.items.map((user) => (
                    <UserRow
                      key={`${user.id}-${user.updated_at}`}
                      user={user}
                      self={user.id === session?.user.id}
                      onChanged={users.reload}
                    />
                  ))}
                </tbody>
              </table>
            </TableScroll>
            <Pagination
              label="Accounts"
              page={page}
              perPage={PER_PAGE}
              total={shown.total}
              onPage={(next) => search.update({ page: next })}
            />
          </div>
        )}
      </section>
    </>
  );
}
