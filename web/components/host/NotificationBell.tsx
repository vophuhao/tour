"use client";

import { useState } from "react";
import { Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Badge } from "@/components/ui/badge";
import { useUnreadCount } from "@/hooks/useNotification";
import Link from "next/link";
import { cn } from "@/lib/utils";

interface NotificationBellProps {
  className?: string;
  showPreview?: boolean;
}

export function NotificationBell({
  className,
  showPreview = false,
}: NotificationBellProps) {
  const [open, setOpen] = useState(false);
  const { data } = useUnreadCount({ role: 'host' });
  const unreadCount = data?.unreadCount || 0;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn("relative", className)}
        >
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <Badge
              variant="destructive"
              className="absolute -top-1 -right-1 h-5 min-w-5 flex items-center justify-center p-0 text-xs"
            >
              {unreadCount > 99 ? "99+" : unreadCount}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>

      {showPreview && (
        <PopoverContent className="w-80 p-4" align="end">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-sm">Thông báo</h3>
              <Badge variant="secondary" className="text-xs">
                {unreadCount} mới
              </Badge>
            </div>

            <div className="space-y-2">
              <p className="text-sm text-gray-600">
                Bạn có {unreadCount} thông báo chưa đọc
              </p>
              <Link
                href="/host/notifications"
                onClick={() => setOpen(false)}
                className="block"
              >
                <Button variant="outline" size="sm" className="w-full">
                  Xem tất cả thông báo
                </Button>
              </Link>
            </div>
          </div>
        </PopoverContent>
      )}
    </Popover>
  );
}
