import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { mockApi } from '../test/api';
import { BarChart } from './BarChart';
import { FilterBar } from './FilterBar';
import { Pagination } from './Pagination';
import { ProtocolTree } from './ProtocolTree';

describe('ProtocolTree', () => {
  it('shows header fields but never anything that could hold packet contents', () => {
    const secret = 'FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER';
    render(
      <ProtocolTree
        layers={[
          { layer: 'udp', source_port: 53, destination_port: 40000, payload_length: 24, payload: secret },
          { layer: 'dns', data: secret, raw: secret, hex: secret, answers: [{ name: 'a.example', bytes: secret }] },
        ]}
      />,
    );
    expect(screen.getByText('UDP')).toBeInTheDocument();
    expect(screen.getByText('payload length')).toBeInTheDocument();
    expect(screen.getByText('a.example')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(secret);
  });
});

describe('Pagination', () => {
  it('shows the range and disables buttons at the ends', async () => {
    const onPage = vi.fn();
    render(<Pagination label="Packets" page={1} perPage={50} total={120} onPage={onPage} />);
    expect(screen.getByText('1–50 of 120')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(onPage).toHaveBeenCalledWith(2);
    await userEvent.click(screen.getByRole('button', { name: 'Last' }));
    expect(onPage).toHaveBeenCalledWith(3);
  });
});

describe('BarChart', () => {
  it('gives screen readers the numbers as a table', () => {
    render(<BarChart title="Packets by protocol" bars={[{ label: 'tcp', value: 1200 }, { label: 'udp', value: 0 }]} />);
    const table = screen.getByRole('table', { name: 'Packets by protocol' });
    expect(table).toHaveTextContent('tcp1,200');
    expect(screen.getByRole('figure', { name: 'Packets by protocol' })).toBeInTheDocument();
  });

  it('says when there is nothing to show', () => {
    render(<BarChart title="Alerts" bars={[]} />);
    expect(screen.getByText('No data')).toBeInTheDocument();
  });
});

describe('FilterBar', () => {
  it('checks filters with the server and applies only valid ones', async () => {
    mockApi([
      [
        'GET',
        /filter=tcp(&|$)/,
        () => ({ body: { valid: true, target: 'packets', normalized: 'tcp', parameters: 0 } }),
      ],
      [
        'GET',
        /filter=tcp\+and\+%C3%A9|filter=tcp%20and%20%C3%A9/,
        () => ({
          status: 400,
          body: { error: { code: 'unexpected_character', message: 'unexpected character', position: { start: 8, end: 10 } } },
        }),
      ],
    ]);
    const onApply = vi.fn();
    render(<FilterBar target="packets" value="" onApply={onApply} />);
    const input = screen.getByLabelText('Display filter');
    await userEvent.type(input, 'tcp and é');
    await waitFor(() => expect(screen.getByText('unexpected character')).toBeInTheDocument());
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    // The problem is marked in the echo of the filter.
    expect(document.querySelector('mark')?.textContent).toBe('é');

    await userEvent.clear(input);
    await userEvent.type(input, 'tcp');
    await waitFor(() => expect(screen.getByText(/Valid filter/)).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect(onApply).toHaveBeenCalledWith('tcp');
  });

  it('applies an empty filter to clear it', async () => {
    mockApi([]);
    const onApply = vi.fn();
    render(<FilterBar target="flows" value="udp" onApply={onApply} />);
    await userEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(onApply).toHaveBeenCalledWith('');
  });
});
