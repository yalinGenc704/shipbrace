import { useCallback, useEffect, useState } from "react";

const KEY = "shipbrace.reviewed.v1";

/**
 * Which "needs your check" items the user has ticked off, and which risks
 * they marked as intended (a public page, records everyone may see). Risk ids
 * contain "@" and item ids never do, so both live in one set.
 *
 * This lives in browser storage on purpose: it is a per-person convenience that
 * should survive a refresh, and losing it costs nothing but a few ticks. It is
 * deliberately NOT the record of whether an app is safe -- that must come from
 * the server once it exists, because it has to be the same for everyone on a
 * team and must not be clearable by emptying site data.
 *
 * Every access is guarded: storage throws in private windows and can come back
 * empty after a clear, and the page has to render correctly when it does.
 */
function read(): Set<string> {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return new Set();

    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? new Set(parsed.filter((v) => typeof v === "string")) : new Set();
  } catch {
    return new Set();
  }
}

function write(ids: Set<string>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify([...ids]));
  } catch {
    // Storage unavailable or full. The tick simply does not persist.
  }
}

export interface ReviewedState {
  isReviewed: (id: string) => boolean;
  toggle: (id: string) => void;
  count: number;
}

export function useReviewed(): ReviewedState {
  const [ids, setIds] = useState<Set<string>>(() => new Set());

  // Read after mount rather than during render, so the first paint does not
  // depend on storage that may throw.
  useEffect(() => setIds(read()), []);

  const toggle = useCallback((id: string) => {
    setIds((previous) => {
      const next = new Set(previous);
      if (!next.delete(id)) next.add(id);
      write(next);
      return next;
    });
  }, []);

  return {
    isReviewed: useCallback((id: string) => ids.has(id), [ids]),
    toggle,
    count: ids.size,
  };
}
