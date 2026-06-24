'use client';

import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { GitCompare } from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';

interface CompareButtonProps {
  propertyId: string;
  className?: string;
  variant?: 'default' | 'ghost' | 'outline' | 'secondary';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  showLabel?: boolean;
}

export function CompareButton({
  propertyId,
  className,
  variant = 'ghost',
  size = 'icon',
  showLabel = false,
}: CompareButtonProps) {
  const [isCompared, setIsCompared] = useState(false);

  // Sync state with localStorage on mount and when compare-updated event fires
  useEffect(() => {
    const checkCompareStatus = () => {
      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem('campsite_compare_ids');
        const compareIds: string[] = stored ? JSON.parse(stored) : [];
        setIsCompared(compareIds.includes(propertyId));
      }
    };

    checkCompareStatus();
    window.addEventListener('compare-updated', checkCompareStatus);

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'campsite_compare_ids') {
        checkCompareStatus();
      }
    };
    window.addEventListener('storage', handleStorageChange);

    return () => {
      window.removeEventListener('compare-updated', checkCompareStatus);
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [propertyId]);

  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (typeof window === 'undefined') return;

    const stored = localStorage.getItem('campsite_compare_ids');
    let compareIds: string[] = stored ? JSON.parse(stored) : [];

    if (compareIds.includes(propertyId)) {
      // Remove
      compareIds = compareIds.filter((id) => id !== propertyId);
      localStorage.setItem('campsite_compare_ids', JSON.stringify(compareIds));
      window.dispatchEvent(new Event('compare-updated'));
      toast.success('Đã xóa khỏi danh sách so sánh');
    } else {
      // Add (limit to 3)
      if (compareIds.length >= 3) {
        toast.error('Chỉ có thể so sánh tối đa 3 địa điểm cùng lúc');
        return;
      }
      compareIds.push(propertyId);
      localStorage.setItem('campsite_compare_ids', JSON.stringify(compareIds));
      window.dispatchEvent(new Event('compare-updated'));
      toast.success('Đã thêm vào danh sách so sánh');
    }
  };

  const button = (
    <Button
      variant={variant}
      size={size}
      onClick={handleClick}
      className={cn(
        'rounded-full transition-all duration-200',
        isCompared && 'bg-primary text-white hover:bg-primary/95',
        className,
      )}
    >
      <GitCompare
        className={cn('h-4 w-4 transition-all', isCompared && 'rotate-180')}
      />
      {showLabel && (
        <span className="ml-2">{isCompared ? 'Đang so sánh' : 'So sánh'}</span>
      )}
    </Button>
  );

  if (!showLabel) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>{button}</TooltipTrigger>
          <TooltipContent>
            <p>{isCompared ? 'Xóa khỏi danh sách so sánh' : 'Thêm vào so sánh'}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return button;
}
