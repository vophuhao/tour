'use client';

import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useTogglePropertyFavorite } from '@/hooks/useFavorite';
import { cn } from '@/lib/utils';
import { Heart } from 'lucide-react';

interface FavoriteButtonProps {
  propertyId: string;
  className?: string;
  variant?: 'default' | 'ghost' | 'outline';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  showLabel?: boolean;
}

export function FavoriteButton({
  propertyId,
  className,
  variant = 'ghost',
  size = 'icon',
  showLabel = false,
}: FavoriteButtonProps) {
  const { toggle, isLoading, isInStore } = useTogglePropertyFavorite();
  const isFavorited = isInStore(propertyId);

  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    toggle(propertyId);
  };

  const button = (
    <Button
      variant={variant}
      size={size}
      onClick={handleClick}
      disabled={isLoading}
      className={cn(
        'rounded-full transition-all duration-200 cursor-pointer',
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
