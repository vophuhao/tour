'use client';

import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useToggleSiteFavorite } from '@/hooks/useFavorite';
import { cn } from '@/lib/utils';
import { Heart } from 'lucide-react';

interface SiteFavoriteButtonProps {
  siteId: string;
  className?: string;
  variant?: 'default' | 'ghost' | 'outline';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  showLabel?: boolean;
}

export function SiteFavoriteButton({
  siteId,
  className,
  variant = 'ghost',
  size = 'icon',
  showLabel = false,
}: SiteFavoriteButtonProps) {
  const { toggle, isLoading, isInStore } = useToggleSiteFavorite();
  const isFavorited = isInStore(siteId);

  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    toggle(siteId);
  };

  const button = (
    <Button
      variant={variant}
      size={size}
      onClick={handleClick}
      disabled={isLoading}
      className={cn(
        'transition-all duration-200 cursor-pointer',
        isFavorited && 'text-red-500 hover:text-red-600',
        className,
      )}
    >
      <Heart
        className={cn('h-5 w-5 transition-all', isFavorited && 'fill-current')}
      />
      {showLabel && (
        <span className="ml-2">{isFavorited ? 'Đã lưu' : 'Lưu'}</span>
      )}
    </Button>
  );

  if (!showLabel) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>{button}</TooltipTrigger>
          <TooltipContent>
            <p>{isFavorited ? 'Xóa khỏi yêu thích' : 'Thêm vào yêu thích'}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return button;
}
