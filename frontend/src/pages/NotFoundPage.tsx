import { Link } from 'react-router';

import { PageHeader } from '../components/Layout';
import { useTitle } from '../lib/useTitle';

export function NotFoundPage() {
  useTitle('Not found');
  return (
    <>
      <PageHeader title="Page not found" />
      <p>
        There is nothing at this address. Go to the <Link to="/">overview</Link>.
      </p>
    </>
  );
}
