'use client';

import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';

interface SuperhostBadgeProps {
  size?: 'xs' | 'sm' | 'md' | 'lg';
  showTooltip?: boolean;
  showLabel?: boolean;
  superhostSince?: string | Date;
  className?: string;
}

const sizeConfig = {
  xs: { container: 'gap-0.5 px-1.5 py-0.5', text: 'text-[10px]', emoji: 'text-xs' },
  sm: { container: 'gap-1 px-2 py-0.5', text: 'text-xs', emoji: 'text-sm' },
  md: { container: 'gap-1.5 px-2.5 py-1', text: 'text-sm', emoji: 'text-base' },
  lg: { container: 'gap-2 px-3 py-1.5', text: 'text-base', emoji: 'text-lg' },
};

export function SuperhostBadge({
  size = 'sm',
  showTooltip = true,
  showLabel = true,
  superhostSince,
  className,
}: SuperhostBadgeProps) {
  const config = sizeConfig[size];

  const badge = (
    <div
      className={cn(
        'inline-flex items-center rounded-full border border-amber-300 bg-gradient-to-r from-amber-50 to-yellow-50 font-medium text-amber-800 shadow-sm',
        config.container,
        className,
      )}
    >
      <span className={config.emoji}>🏅</span>
      {showLabel && (
        <span className={cn('font-semibold', config.text)}>Superhost</span>
      )}
    </div>
  );

  if (!showTooltip) return badge;

  const sinceText = superhostSince
    ? `Đạt danh hiệu từ ${format(new Date(superhostSince), 'MM/yyyy', { locale: vi })}`
    : null;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          {badge}
        </TooltipTrigger>
        <TooltipContent className="max-w-[220px] text-center" side="top">
          <p className="font-semibold text-amber-400 dark:text-amber-700">🏅 Superhost</p>
          <p className="mt-1 text-xs text-zinc-300 dark:text-zinc-700">
            Host xuất sắc với rating ≥ 4.8, tỷ lệ phản hồi ≥ 90% và hơn 10 chuyến đi thành công.
          </p>
          {sinceText && (
            <p className="mt-1 text-xs text-zinc-400 dark:text-zinc-500">{sinceText}</p>
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
