/**
 * DataTable — generic, sortable, keyboard-accessible table.
 *
 * - Semantic <table>/<thead>/<tbody>/<th scope="col">.
 * - Sorting lives in a real <button> inside each sortable <th>, so it is
 *   reachable and operable by keyboard with a visible focus ring.
 * - aria-sort on the <th> announces the current sort to screen readers.
 * - No API calls and no business logic: rows come in via props.
 */

import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';

export interface Column<T> {
  key: string;
  header: string;
  /** Cell renderer. Receives the whole row. */
  render: (row: T) => ReactNode;
  /** Supply to make the column sortable. Must return a comparable primitive. */
  sortValue?: (row: T) => string | number;
  /** Fixed/intrinsic width hint, e.g. "120px" or "minmax(0,2fr)". */
  width?: string;
  /** Adds a class to every cell in the column, e.g. for monospace or clamping. */
  cellClassName?: string;
  /** Hidden below ~1280px to keep the table usable on smaller laptops. */
  secondary?: boolean;
}

export type SortDirection = 'asc' | 'desc';

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** Accessible name for the table. Required. */
  caption: string;
  /** Renders the caption visibly rather than for screen readers only. */
  showCaption?: boolean;
  defaultSortKey?: string;
  defaultSortDirection?: SortDirection;
  onRowClick?: (row: T) => void;
  /** Marks a row as needing attention, e.g. critical severity. */
  rowClassName?: (row: T) => string | undefined;
  emptyLabel?: string;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  showCaption = false,
  defaultSortKey,
  defaultSortDirection = 'desc',
  onRowClick,
  rowClassName,
  emptyLabel = 'No rows to display.',
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | undefined>(defaultSortKey);
  const [direction, setDirection] = useState<SortDirection>(defaultSortDirection);

  const sortedRows = useMemo(() => {
    const column = columns.find((c) => c.key === sortKey);
    if (!column?.sortValue) return rows;

    const getValue = column.sortValue;
    return [...rows].sort((a, b) => {
      const av = getValue(a);
      const bv = getValue(b);
      let result: number;
      if (typeof av === 'number' && typeof bv === 'number') {
        result = av - bv;
      } else {
        result = String(av).localeCompare(String(bv));
      }
      return direction === 'asc' ? result : -result;
    });
  }, [rows, columns, sortKey, direction]);

  function toggleSort(key: string) {
    if (key === sortKey) {
      setDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setDirection('desc');
    }
  }

  return (
    <div className="data-table-wrap">
      <table className="data-table">
        <caption className={showCaption ? 'data-table__caption' : 'sr-only'}>
          {caption}
        </caption>
        <thead>
          <tr>
            {columns.map((column) => {
              const isSorted = column.key === sortKey;
              const ariaSort = !column.sortValue
                ? undefined
                : isSorted
                  ? direction === 'asc'
                    ? 'ascending'
                    : 'descending'
                  : 'none';

              return (
                <th
                  key={column.key}
                  scope="col"
                  aria-sort={ariaSort}
                  style={column.width ? { width: column.width } : undefined}
                  className={column.secondary ? 'data-table__col--secondary' : undefined}
                >
                  {column.sortValue ? (
                    <button
                      type="button"
                      className={`data-table__sort${isSorted ? ' data-table__sort--active' : ''}`}
                      onClick={() => toggleSort(column.key)}
                    >
                      <span>{column.header}</span>
                      <span className="data-table__sort-icon" aria-hidden="true">
                        {isSorted ? (direction === 'asc' ? '▲' : '▼') : '⇅'}
                      </span>
                      <span className="sr-only">
                        {isSorted
                          ? `, sorted ${direction === 'asc' ? 'ascending' : 'descending'}. Activate to reverse.`
                          : ', not sorted. Activate to sort.'}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sortedRows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="data-table__empty">
                {emptyLabel}
              </td>
            </tr>
          ) : (
            sortedRows.map((row) => {
              const extra = rowClassName?.(row);
              return (
                <tr
                  key={rowKey(row)}
                  className={`${onRowClick ? 'data-table__row--clickable' : ''}${
                    extra ? ` ${extra}` : ''
                  }`}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                >
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={`${column.cellClassName ?? ''}${
                        column.secondary ? ' data-table__col--secondary' : ''
                      }`}
                    >
                      {column.render(row)}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
