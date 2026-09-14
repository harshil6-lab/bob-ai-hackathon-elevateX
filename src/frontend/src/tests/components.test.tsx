/**
 * Reusable component tests.
 *
 * The load-bearing assertions here are the two design invariants:
 *   - severity is never conveyed by colour alone (colour + shape + text)
 *   - confidence is never rendered in the severity idiom
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SeverityBadge } from '../components/SeverityBadge';
import { ConfidenceIndicator } from '../components/ConfidenceIndicator';
import { StatCard } from '../components/StatCard';
import { DataTable } from '../components/DataTable';
import type { Column } from '../components/DataTable';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { MitreChip, mitreUrl } from '../components/MitreChip';
import { BlufPanel } from '../components/BlufPanel';
import { EvidencePanel } from '../components/EvidencePanel';
import { ActionsList } from '../components/ActionsList';

describe('SeverityBadge', () => {
  it.each(['critical', 'high', 'medium', 'low'] as const)(
    'renders %s with a text label AND a non-colour shape glyph',
    (severity) => {
      const { container } = render(<SeverityBadge severity={severity} />);

      // 1. text label — readable with no colour perception at all
      const label = container.querySelector('.severity-badge__label');
      expect(label?.textContent?.toLowerCase()).toBe(severity);

      // 2. shape glyph — the non-colour cue
      const glyph = container.querySelector('.severity-badge__glyph');
      expect(glyph?.textContent).toBeTruthy();
      expect(glyph).toHaveAttribute('aria-hidden', 'true');
    },
  );

  it('gives each severity a DISTINCT shape, so greyscale stays unambiguous', () => {
    const glyphs = (['critical', 'high', 'medium', 'low'] as const).map((severity) => {
      const { container } = render(<SeverityBadge severity={severity} />);
      return container.querySelector('.severity-badge__glyph')?.textContent;
    });
    expect(new Set(glyphs).size).toBe(4);
  });

  it('reports an unrecognised severity honestly rather than inventing one', () => {
    render(<SeverityBadge severity="catastrophic" />);
    expect(screen.getByText('catastrophic')).toBeInTheDocument();
  });

  it('does not crash on null or undefined', () => {
    expect(() => render(<SeverityBadge severity={null} />)).not.toThrow();
    expect(() => render(<SeverityBadge severity={undefined} />)).not.toThrow();
  });
});

describe('ConfidenceIndicator', () => {
  it('renders a meter with the numeric percentage', () => {
    render(<ConfidenceIndicator confidence={94} />);
    expect(screen.getByText('94%')).toBeInTheDocument();
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '94');
  });

  it('is visually and structurally distinct from SeverityBadge', () => {
    const { container: conf } = render(<ConfidenceIndicator confidence={94} />);
    const { container: sev } = render(<SeverityBadge severity="critical" />);

    // A meter, not a badge; a badge, not a meter. No shared class or role.
    expect(conf.querySelector('.confidence')).toBeTruthy();
    expect(conf.querySelector('.severity-badge')).toBeNull();
    expect(sev.querySelector('.severity-badge')).toBeTruthy();
    expect(sev.querySelector('.confidence')).toBeNull();
    expect(within(sev as HTMLElement).queryByRole('meter')).toBeNull();
  });

  it('tolerates a 0-1 float without rendering it as 1%', () => {
    render(<ConfidenceIndicator confidence={0.94} />);
    expect(screen.getByText('94%')).toBeInTheDocument();
  });

  it('says so plainly when confidence is not reported', () => {
    render(<ConfidenceIndicator confidence={null} />);
    expect(screen.getByText('Not reported')).toBeInTheDocument();
  });
});

describe('StatCard', () => {
  it('renders label, value and context', () => {
    render(<StatCard label="Alerts ingested" value="248" context="across 4 feeds" />);
    expect(screen.getByText('Alerts ingested')).toBeInTheDocument();
    expect(screen.getByText('248')).toBeInTheDocument();
    expect(screen.getByText('across 4 feeds')).toBeInTheDocument();
  });

  it('renders a real zero rather than falling through to a placeholder', () => {
    render(<StatCard label="Critical" value={0} />);
    expect(screen.getByText('0')).toBeInTheDocument();
  });

  it('shows a placeholder when the value is genuinely absent', () => {
    render(<StatCard label="Critical" value={undefined} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});

describe('DataTable', () => {
  interface Row {
    id: string;
    score: number;
  }
  const rows: Row[] = [
    { id: 'B', score: 2 },
    { id: 'A', score: 3 },
    { id: 'C', score: 1 },
  ];
  const columns: Column<Row>[] = [
    { key: 'id', header: 'ID', render: (r) => r.id, sortValue: (r) => r.id },
    { key: 'score', header: 'Score', render: (r) => r.score, sortValue: (r) => r.score },
  ];

  it('renders a semantic table with an accessible caption', () => {
    render(<DataTable caption="Test rows" columns={columns} rows={rows} rowKey={(r) => r.id} />);
    expect(screen.getByRole('table', { name: 'Test rows' })).toBeInTheDocument();
    expect(screen.getAllByRole('columnheader')).toHaveLength(2);
  });

  it('exposes sorting through real buttons, so it is keyboard-operable', async () => {
    const user = userEvent.setup();
    render(<DataTable caption="Test rows" columns={columns} rows={rows} rowKey={(r) => r.id} />);

    const sortButton = screen.getByRole('button', { name: /^Score/ });

    // Reachable and activatable by keyboard alone.
    sortButton.focus();
    expect(sortButton).toHaveFocus();
    await user.keyboard('{Enter}');

    const header = sortButton.closest('th');
    expect(header).toHaveAttribute('aria-sort', 'descending');

    const firstCell = screen.getAllByRole('row')[1].querySelectorAll('td')[1];
    expect(firstCell.textContent).toBe('3');
  });

  it('reverses direction when the same header is activated again', async () => {
    const user = userEvent.setup();
    render(<DataTable caption="Test rows" columns={columns} rows={rows} rowKey={(r) => r.id} />);
    const sortButton = screen.getByRole('button', { name: /^Score/ });

    await user.click(sortButton);
    await user.click(sortButton);

    expect(sortButton.closest('th')).toHaveAttribute('aria-sort', 'ascending');
    expect(screen.getAllByRole('row')[1].querySelectorAll('td')[1].textContent).toBe('1');
  });

  it('renders an empty message when there are no rows', () => {
    render(
      <DataTable
        caption="Test rows"
        columns={columns}
        rows={[]}
        rowKey={(r) => r.id}
        emptyLabel="Nothing here"
      />,
    );
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
  });
});

describe('LoadingSkeleton', () => {
  it('announces itself as busy to assistive technology', () => {
    render(<LoadingSkeleton variant="card" count={3} label="Loading incidents…" />);
    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByText('Loading incidents…')).toBeInTheDocument();
  });

  it('renders the requested number of units', () => {
    const { container } = render(<LoadingSkeleton variant="row" count={4} />);
    expect(container.querySelectorAll('.skeleton')).toHaveLength(4);
  });
});

describe('EmptyState', () => {
  it('renders the message and an optional action', async () => {
    const user = userEvent.setup();
    const onClick = vi.fn();
    render(<EmptyState message="Nothing matched" action={{ label: 'Clear', onClick }} />);

    expect(screen.getByText('Nothing matched')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('renders without an action', () => {
    render(<EmptyState message="Nothing here" />);
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('ErrorState', () => {
  it('always offers a visible, working Retry when a retry handler is given', async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    render(<ErrorState message="Request failed" detail="HTTP 500" onRetry={onRetry} />);

    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Request failed')).toBeInTheDocument();
    expect(screen.getByText('HTTP 500')).toBeInTheDocument();

    const retry = screen.getByRole('button', { name: 'Retry' });
    expect(retry).toBeVisible();
    await user.click(retry);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

describe('MitreChip', () => {
  it('builds the correct ATT&CK URL, path-segmenting sub-techniques', () => {
    expect(mitreUrl('T1055')).toBe('https://attack.mitre.org/techniques/T1055/');
    expect(mitreUrl('T1059.001')).toBe('https://attack.mitre.org/techniques/T1059/001/');
  });

  it('links out in a new tab with rel="noopener noreferrer"', () => {
    render(<MitreChip technique={{ id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory' }} />);
    const link = screen.getByRole('link');
    expect(link).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1003/001/');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('shows the ID alone when the API supplied no name — it invents none', () => {
    const { container } = render(<MitreChip technique="T1046" />);
    expect(screen.getByText('T1046')).toBeInTheDocument();
    expect(container.querySelector('.mitre-chip__name')).toBeNull();
  });

  it('shows the name only when the API actually supplied it', () => {
    render(<MitreChip technique={{ id: 'T1055', name: 'Process Injection' }} />);
    expect(screen.getByText('Process Injection')).toBeInTheDocument();
  });
});

describe('BlufPanel', () => {
  const longBluf =
    'A confirmed intrusion is in progress on SERVER-17 and has spread to FILE-SRV-31. ' +
    'Credential material was read from LSASS and replayed over SMB. Isolate both hosts now.';

  it('is labelled BLUF and expands the acronym', () => {
    render(<BlufPanel bluf={longBluf} />);
    expect(screen.getByRole('heading', { name: 'BLUF' })).toBeInTheDocument();
    expect(screen.getByText('Bottom Line Up Front')).toBeInTheDocument();
  });

  it('renders the backend text verbatim and in full — never truncated', () => {
    const { container } = render(<BlufPanel bluf={longBluf} />);
    const text = container.querySelector('.bluf__text');
    expect(text?.textContent).toBe(longBluf);
    // No ellipsis inserted anywhere.
    expect(text?.textContent).not.toContain('…');
    expect(text?.textContent).not.toMatch(/\.\.\.$/);
  });

  it('says plainly when no BLUF was returned', () => {
    render(<BlufPanel bluf="" />);
    expect(screen.getByText(/No BLUF summary was returned/)).toBeInTheDocument();
  });
});

describe('EvidencePanel', () => {
  it('renders only the fields actually present in the response', () => {
    const { container } = render(
      <EvidencePanel
        evidence={[
          {
            alert_id: 'ALT-1004',
            source: 'SIEM',
            host: 'SERVER-17',
            description: 'Handle opened to lsass.exe.',
          },
        ]}
      />,
    );

    expect(screen.getByText('ALT-1004')).toBeInTheDocument();
    expect(screen.getByText('SIEM')).toBeInTheDocument();
    expect(screen.getByText('SERVER-17')).toBeInTheDocument();

    // Fields the response omitted are simply absent — no "N/A" placeholder.
    const labels = Array.from(container.querySelectorAll('.evidence-item__field-label')).map(
      (el) => el.textContent,
    );
    expect(labels).not.toContain('User');
    expect(labels).not.toContain('Source IP');
    expect(container.textContent).not.toContain('N/A');
  });

  it('handles the bare-string evidence form', () => {
    render(<EvidencePanel evidence={['ALT-2221 — SIEM — WKS-0142 — port scan.']} />);
    expect(screen.getByText(/ALT-2221/)).toBeInTheDocument();
  });

  it('shows an EmptyState rather than a fabricated placeholder when empty', () => {
    render(<EvidencePanel evidence={[]} />);
    expect(screen.getByText(/No evidence records were returned/)).toBeInTheDocument();
  });
});

describe('ActionsList', () => {
  it('frames actions as recommended, never as completed', () => {
    const { container } = render(
      <ActionsList
        actions={[
          { action: 'Isolate SERVER-17', priority: 'immediate', rationale: 'C2 is live.' },
        ]}
      />,
    );

    expect(screen.getByText('Isolate SERVER-17')).toBeInTheDocument();
    expect(screen.getByText(/None of these has been executed/)).toBeInTheDocument();

    // No completion affordance or past-tense claim anywhere.
    const text = container.textContent ?? '';
    expect(text).not.toMatch(/completed/i);
    expect(text).not.toMatch(/\bdone\b/i);
    expect(container.querySelector('input[type="checkbox"]')).toBeNull();
  });

  it('handles the bare-string action form', () => {
    render(<ActionsList actions={['Reset the admin credential.']} />);
    expect(screen.getByText('Reset the admin credential.')).toBeInTheDocument();
  });

  it('shows an EmptyState when there are no actions', () => {
    render(<ActionsList actions={[]} />);
    expect(screen.getByText(/No recommended actions were returned/)).toBeInTheDocument();
  });
});
