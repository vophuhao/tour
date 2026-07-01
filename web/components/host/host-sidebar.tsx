'use client';

import { logout } from '@/lib/client-actions';
import { cn } from '@/lib/utils';
import { useAuthStore } from '@/store/auth.store';
import { useUnreadCount } from '@/hooks/useNotification';
import { useUnreadMessagesCount } from '@/hooks/useUnreadMessagesCount';
import {
  Bell,
  Calendar,
  ChevronLeft,
  ChevronRight,
  Home,
  LogOut,
  MessageSquare,
  Moon,
  Star,
  Sun,
  Tent,
  User,
  DollarSign,
  Wallet,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { useTheme } from 'next-themes';

type MenuItem = {
  name: string;
  href?: string;
  icon: React.ComponentType<{ className?: string }>;
  action?: () => void;
  group?: 'main' | 'account';
};

type SidebarProps = {
  collapsed: boolean;
  setCollapsed: (val: boolean) => void;
};

export default function HostSidebar({ collapsed, setCollapsed }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const { user } = useAuthStore();
  const { data: unreadData } = useUnreadCount();
  const unreadCount = unreadData?.unreadCount || 0;
  const { data: unreadMessagesData } = useUnreadMessagesCount();
  const unreadMessagesCount = unreadMessagesData?.unreadCount || 0;

  const [sidebarMounted, setSidebarMounted] = useState(false);

  useEffect(() => {
    setSidebarMounted(true);
  }, []);

  const handleLogout = async () => {
    const response = await logout();
    if (response.success) {
      toast.success(response.message);
      useAuthStore.getState().setUser(null);
      router.push('/sign-in');
    }
  };

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  const mainMenuItems: MenuItem[] = [
    { name: 'Dashboard', href: '/host', icon: Home, group: 'main' },
    { name: 'Booking & Lịch', href: '/host/bookings', icon: Calendar, group: 'main' },
    // { name: 'Lịch & Giá mùa', href: '/host/calendar', icon: Calendar, group: 'main' },
    { name: 'Khu đất', href: '/host/properties', icon: Tent, group: 'main' },
    { name: 'Thông báo', href: '/host/notifications', icon: Bell, group: 'main' },
    { name: 'Đánh giá', href: '/host/reviews', icon: Star, group: 'main' },
    { name: 'Doanh thu', href: '/host/revenue', icon: DollarSign, group: 'main' },
    { name: 'Ví của tôi', href: '/host/wallet', icon: Wallet, group: 'main' },
    { name: 'Hỗ trợ', href: '/host/support', icon: MessageSquare, group: 'main' },
  ];

  const userInitial = user?.username?.charAt(0).toUpperCase() || 'H';

  return (
    <aside
      className={cn(
        'fixed top-0 left-0 h-screen bg-custom-sidebar border-r border-custom-sidebar-border shadow-2xl flex flex-col transition-all duration-300 z-50',
        collapsed ? 'w-16' : 'w-56',
      )}
    >
      {/* ── Logo + Brand ── */}
      <div className={cn(
        "relative flex h-16 items-center border-b border-custom-sidebar-border/60 px-4",
        collapsed ? "justify-center" : "justify-center"
      )}>
        {!collapsed && (
          <Link href={'/'} className="text-xl font-bold text-white tracking-wide truncate">
            HDCAMPING
          </Link>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            "p-1.5 rounded-lg text-slate-300 hover:bg-custom-sidebar-hover hover:text-white transition-colors",
            !collapsed ? "absolute right-4" : ""
          )}
          title={collapsed ? 'Mở rộng sidebar' : 'Thu gọn sidebar'}
        >
          <ChevronRight className={cn("h-4 w-4 transition-transform duration-300", !collapsed && "rotate-180")} />
        </button>
      </div>

      {/* ── Main Navigation ── */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1.5 scrollbar-hide">
        {mainMenuItems.map(item => {
          const Icon = item.icon;
          const isActive = item.href === '/host' ? pathname === '/host' : pathname.startsWith(item.href!);

          return (
            <Link
              key={item.name}
              href={item.href!}
              title={collapsed ? item.name : undefined}
              className={cn(
                'group relative flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary/15 text-primary'
                  : 'text-slate-200 hover:bg-custom-sidebar-hover/70 hover:text-white',
              )}
            >
              {/* Icon + badge */}
              <div className="relative flex-shrink-0">
                <Icon className={cn("h-4.5 w-4.5 transition-colors", isActive ? "text-primary" : "text-slate-400 group-hover:text-slate-100")} />
                {item.name === 'Thông báo' && unreadCount > 0 && (
                  <span className="absolute -top-1.5 -right-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white px-1">
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
                {item.name === 'Hỗ trợ' && unreadMessagesCount > 0 && (
                  <span className="absolute -top-1.5 -right-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white px-1">
                    {unreadMessagesCount > 9 ? '9+' : unreadMessagesCount}
                  </span>
                )}
              </div>

              {/* Label */}
              <span
                className={cn(
                  'flex-1 truncate transition-all duration-300 text-left',
                  collapsed ? 'w-0 overflow-hidden opacity-0' : 'opacity-100',
                )}
              >
                {item.name}
              </span>

              {/* Active indicator bar */}
              {isActive && (
                <div className="absolute left-0 top-1/2 h-7 w-0.5 -translate-y-1/2 rounded-r bg-primary" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* ── Bottom Section ── */}
      <div className="border-t border-custom-sidebar-border/60 p-3 space-y-1.5 bg-black/20">
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          title={sidebarMounted && theme === 'dark' ? 'Chuyển sang sáng' : 'Chuyển sang tối'}
          className={cn(
            'flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-semibold transition-colors',
            'text-slate-200 hover:bg-custom-sidebar-hover/50 hover:text-white',
          )}
        >
          <div className="relative flex-shrink-0 h-4 w-4">
            <Sun className={cn('absolute inset-0 h-4 w-4 transition-all duration-250', sidebarMounted && theme === 'dark' ? 'scale-0 opacity-0' : 'scale-100 opacity-100')} />
            <Moon className={cn('absolute inset-0 h-4 w-4 transition-all duration-250', sidebarMounted && theme === 'dark' ? 'scale-100 opacity-100' : 'scale-0 opacity-0')} />
          </div>
          <span className={cn('flex-1 truncate transition-all duration-300 text-left', collapsed ? 'w-0 overflow-hidden opacity-0' : 'opacity-100')}>
            {sidebarMounted && theme === 'dark' ? 'Giao diện tối' : 'Giao diện sáng'}
          </span>
        </button>

        {/* Logout */}
        <button
          onClick={handleLogout}
          title="Đăng xuất"
          className={cn(
            'flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-semibold transition-colors',
            'text-slate-200 hover:bg-red-950/20 hover:text-red-400',
          )}
        >
          <LogOut className="h-4 w-4 flex-shrink-0" />
          <span className={cn('flex-1 truncate transition-all duration-300 text-left', collapsed ? 'w-0 overflow-hidden opacity-0' : 'opacity-100')}>
            Đăng xuất
          </span>
        </button>

        {/* User Info */}
        <div
          className={cn(
            'flex items-center gap-3 rounded-lg p-2 border border-custom-sidebar-border/40 bg-black/20 transition-all duration-200',
            collapsed ? 'justify-center' : '',
          )}
        >
          {/* Avatar */}
          <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-slate-700 text-slate-200 text-sm font-bold ring-2 ring-slate-700">
            {userInitial}
          </div>
          <div className={cn('min-w-0 transition-all duration-300 text-left', collapsed ? 'w-0 overflow-hidden opacity-0' : 'opacity-100')}>
            <p className="text-xs font-bold text-white truncate">{user?.username || 'Host'}</p>
            <p className="text-[10px] text-slate-300 truncate">{user?.email || 'host@campo.vn'}</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
