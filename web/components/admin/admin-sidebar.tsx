'use client';

import { logout } from '@/lib/client-actions';
import { cn } from '@/lib/utils';
import { useAuthStore } from '@/store/auth.store';
import { useUnreadCount } from '@/hooks/useNotification';
import {
  BarChart,
  BarChart3,
  Bell,
  Home,
  LogOut,
  Package,
  Settings,
  Tent,
  Users,
  ChevronDown,
  ChevronRight,
  MessageSquare,
  MapPin,
  Flag,
  CalendarCheck,
  DollarSign,
  Sun,
  Moon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { useTheme } from 'next-themes';

type MenuItem = {
  name: string;
  href?: string;
  icon: React.ComponentType<{ className?: string }>;
  action?: () => void;
  subMenu?: { name: string; href: string }[];
};

type SidebarProps = {
  collapsed: boolean;
  setCollapsed: (val: boolean) => void;
};

export default function Sidebar({ collapsed, setCollapsed }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const { user } = useAuthStore();
  const [hovered, setHovered] = useState<string | null>(null);
  const [expandedMenus, setExpandedMenus] = useState<string[]>([]);
  const { data: unreadData } = useUnreadCount();
  const unreadCount = unreadData?.unreadCount || 0;

  const handleLogout = async () => {
    const response = await logout();
    if (response.success) {
      toast.success(response.message);
      useAuthStore.getState().setUser(null);
      router.push('/sign-in');
    }
  };

  const toggleMenu = (name: string) => {
    setExpandedMenus((prev) =>
      prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name]
    );
  };

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  const userInitial = user?.username?.charAt(0).toUpperCase() || 'A';

  const menuItems: MenuItem[] = [
    { name: 'Dashboard', href: '/admin', icon: Home },
    { name: 'Users', href: '/admin/users', icon: Users },
    { name: 'Host', href: '/admin/hosts', icon: Tent },
    {
      name: 'Nội dung',
      icon: MessageSquare,
      subMenu: [
        { name: 'Bài viết', href: '/admin/forum' },
        { name: 'Địa điểm ', href: '/admin/free-spots' },
      ],
    },
    { name: 'Báo cáo', href: '/admin/reports', icon: Flag },
    { name: 'Booking', href: '/admin/bookings', icon: CalendarCheck },
    { name: 'Doanh thu', href: '/admin/revenue', icon: BarChart3 },
    { name: 'Thanh toán', href: '/admin/payouts', icon: DollarSign },
    { name: 'Thông báo', href: '/admin/notifications', icon: Bell },
    { name: 'Cài đặt', href: '/admin/settings', icon: Settings },
  ];

  return (
    <aside
      className={cn(
        'fixed top-0 left-0 h-screen bg-custom-sidebar border-r border-custom-sidebar-border shadow-2xl flex flex-col transition-all duration-300 z-50',
        collapsed ? 'w-16' : 'w-56'
      )}
    >
      <div className={cn(
        "relative flex h-16 items-center border-b border-custom-sidebar-border/50 px-4",
        collapsed ? "justify-center" : "justify-center"
      )}>
        {!collapsed && (
          <Link href="/" className="text-xl font-bold text-white tracking-wide truncate">
            HDCAMPING
          </Link>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            "p-1.5 rounded-lg text-slate-300 hover:bg-custom-sidebar-hover hover:text-white transition-colors",
            !collapsed ? "absolute right-4" : ""
          )}
          title={collapsed ? 'Mở rộng' : 'Thu gọn'}
        >
          <ChevronRight className={cn("h-4 w-4 transition-transform duration-300", !collapsed && "rotate-180")} />
        </button>
      </div>

      {/* Menu */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto scrollbar-hide">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = item.href === '/admin' ? pathname === '/admin' : (item.href ? pathname.startsWith(item.href) : false);
          const isHovered = hovered === (item.href || item.name);

          const hasSubmenu = !!item.subMenu;
          const isExpanded = expandedMenus.includes(item.name);

          // Submenu active check
          const isSubmenuActive = hasSubmenu && item.subMenu!.some(sub => pathname.startsWith(sub.href));

          const finalClasses = cn(
            'group relative flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200 w-full justify-between cursor-pointer',
            isActive || isSubmenuActive
              ? 'bg-primary/15 text-primary'
              : 'text-slate-200 hover:bg-custom-sidebar-hover/70 hover:text-white'
          );

          const mainContent = (
            <div className="flex items-center gap-3 w-full min-w-0">
              <div className="relative flex-shrink-0">
                <Icon className={cn("h-4.5 w-4.5 transition-colors", (isActive || isSubmenuActive) ? "text-primary" : "text-slate-400 group-hover:text-slate-100")} />
                {item.name === 'Thông báo' && unreadCount > 0 && (
                  <span className="absolute -top-1.5 -right-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white px-1">
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
              </div>
              {!collapsed && (
                <span className="flex-1 truncate text-left">{item.name}</span>
              )}
              {!collapsed && hasSubmenu && (
                <span className="flex-shrink-0">
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5 text-slate-400 group-hover:text-slate-200" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-slate-200" />
                  )}
                </span>
              )}
            </div>
          );

          // Active indicator pill on left edge
          const activeIndicator = (isActive || isSubmenuActive) && (
            <div className="absolute left-0 top-1/2 h-7 w-0.5 -translate-y-1/2 rounded-r bg-primary" />
          );

          if (hasSubmenu) {
            return (
              <div key={item.name} className="space-y-0.5">
                <button
                  onClick={() => toggleMenu(item.name)}
                  onMouseEnter={() => setHovered(item.name)}
                  onMouseLeave={() => setHovered(null)}
                  className={finalClasses}
                >
                  {activeIndicator}
                  {mainContent}
                </button>

                {/* Submenu list */}
                {isExpanded && !collapsed && (
                  <div className="pl-9 pr-2 py-1 flex flex-col gap-1 border-l border-custom-sidebar-border ml-5 mt-1 space-y-1">
                    {item.subMenu!.map((sub) => {
                      const subActive = pathname.startsWith(sub.href);
                      return (
                        <Link
                          key={sub.name}
                          href={sub.href}
                          className={cn(
                            'px-3 py-1.5 rounded-md text-xs transition-colors truncate',
                            subActive
                              ? 'text-primary bg-primary/10 font-semibold'
                              : 'text-slate-300 hover:text-white hover:bg-custom-sidebar-hover/30 font-medium'
                          )}
                        >
                          {sub.name}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          }

          const buttonContent = (
            <>
              {activeIndicator}
              {mainContent}
            </>
          );

          return item.action ? (
            <button
              key={item.name}
              onClick={item.action}
              onMouseEnter={() => setHovered(item.name)}
              onMouseLeave={() => setHovered(null)}
              className={cn(finalClasses, 'hover:bg-red-950/20 hover:text-red-400')}
            >
              {buttonContent}
            </button>
          ) : (
            <Link
              key={item.name}
              href={item.href!}
              onMouseEnter={() => setHovered(item.href!)}
              onMouseLeave={() => setHovered(null)}
              className={finalClasses}
            >
              {buttonContent}
            </Link>
          );
        })}
      </nav>

      {/* ── Bottom Section ── */}
      <div className="border-t border-custom-sidebar-border/60 p-3 space-y-1.5 bg-black/20">
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Chuyển sang sáng' : 'Chuyển sang tối'}
          className={cn(
            'flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-semibold transition-colors',
            'text-slate-200 hover:bg-custom-sidebar-hover/50 hover:text-white',
          )}
        >
          <div className="relative flex-shrink-0 h-4 w-4">
            <Sun className={cn('absolute inset-0 h-4 w-4 transition-all duration-250', theme === 'dark' ? 'scale-0 opacity-0' : 'scale-100 opacity-100')} />
            <Moon className={cn('absolute inset-0 h-4 w-4 transition-all duration-250', theme === 'dark' ? 'scale-100 opacity-100' : 'scale-0 opacity-0')} />
          </div>
          <span className={cn('flex-1 truncate transition-all duration-300 text-left', collapsed ? 'w-0 overflow-hidden opacity-0' : 'opacity-100')}>
            {theme === 'dark' ? 'Giao diện tối' : 'Giao diện sáng'}
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
            <p className="text-xs font-bold text-white truncate">{user?.username || 'Admin'}</p>
            <p className="text-[10px] text-slate-300 truncate">{user?.email || 'admin@campo.vn'}</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
