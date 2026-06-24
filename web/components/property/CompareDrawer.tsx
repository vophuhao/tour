'use client';

import { Button } from '@/components/ui/button';
import { GitCompare } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';

export function CompareDrawer() {
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const updateCompareIds = () => {
      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem('campsite_compare_ids');
        setCompareIds(stored ? JSON.parse(stored) : []);
      }
    };

    updateCompareIds();
    window.addEventListener('compare-updated', updateCompareIds);

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'campsite_compare_ids') {
        updateCompareIds();
      }
    };
    window.addEventListener('storage', handleStorageChange);

    return () => {
      window.removeEventListener('compare-updated', updateCompareIds);
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  const handleClearAll = () => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('campsite_compare_ids', JSON.stringify([]));
      window.dispatchEvent(new Event('compare-updated'));
    }
  };

  if (!mounted || compareIds.length === 0) return null;

  return (
    <div translate="no" className="fixed bottom-6 right-6 z-50 animate-in fade-in slide-in-from-bottom-5 duration-300 notranslate">
      <div className="flex items-center gap-3.5 rounded-2xl border border-slate-200/80 bg-white/95 p-4 shadow-xl backdrop-blur-md dark:border-slate-800 dark:bg-slate-950/95">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <GitCompare className="h-4 w-4" />
          </div>
          <span>So sánh ({compareIds.length}/3) địa điểm</span>
        </div>

        <div className="flex items-center gap-2 border-l border-slate-100 pl-3 dark:border-slate-850">
          <Link href={`/compare?ids=${compareIds.join(',')}`}>
            <Button size="sm" className="rounded-xl font-bold shadow-sm px-4">
              So sánh ngay
            </Button>
          </Link>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleClearAll}
            className="h-8 rounded-xl px-2.5 text-slate-500 hover:text-red-500 hover:bg-red-50/50 dark:hover:bg-red-950/10 transition-colors text-xs font-semibold"
          >
            Xóa hết
          </Button>
        </div>
      </div>
    </div>
  );
}
