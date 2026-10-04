import { useId, useState, type FormEvent } from 'react';
import { Navigate, useSearchParams } from 'react-router';

import { api, toApiError } from '../api/client';
import { safeNext, useAuth } from '../lib/auth';
import { useTitle } from '../lib/useTitle';

export function LoginPage() {
  useTitle('Sign in');
  const { state, signedIn } = useAuth();
  const [params] = useSearchParams();
  const next = safeNext(params.get('next'));
  const usernameId = useId();
  const passwordId = useId();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (state.status === 'signed-in') return <Navigate to={next} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await api.login(username, password);
      setPassword('');
      signedIn(session);
    } catch (caught) {
      const apiError = toApiError(caught);
      setError(
        apiError.code === 'invalid_credentials'
          ? 'The username or password is wrong, or the account is disabled.'
          : apiError.message,
      );
      setBusy(false);
    }
  }

  return (
    <main id="main" className="login">
      <form className="card login-form" onSubmit={submit} aria-labelledby="login-heading">
        <h1 id="login-heading">Sign in to FlowSentinel</h1>
        <p className="muted">
          Use the account an administrator created for you. Analyze only traffic you are authorized to inspect.
        </p>
        <div className="field">
          <label htmlFor={usernameId}>Username</label>
          <input
            id={usernameId}
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor={passwordId}>Password</label>
          <input
            id={passwordId}
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>
        <button type="submit" disabled={busy || !username || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
      </form>
    </main>
  );
}
