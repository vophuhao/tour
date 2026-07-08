'use client';

import { Button } from '@/components/ui/button';
import { logout } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import {
  LayoutDashboard,
  LogOut,
  Menu,
  ShoppingCart,
  User,
  X,
} from 'lucide-react';
import Link from 'next/link';
import Image from 'next/image';
import { usePathname, useRouter } from 'next/navigation';
import { useState } from 'react';
import { useMounted } from '@/hooks/useMounted';
import { ModeToggle } from '@/components/mode-toggle';
import GoogleTranslator from '@/components/GoogleTranslator';

const navItems = [
  { name: 'Trang chủ', href: '/' },
  { name: 'Tìm kiếm', href: '/search' },
  { name: 'Chuyến đi', href: '/roadtrip' },
  { name: 'Điểm cắm trại', href: '/free-spots' },
  { name: 'Diễn đàn', href: '/forum' },
  // { name: 'Giới thiệu', href: '/about' },
  // { name: 'Liên hệ', href: '/contact' },
];

export default function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const { user, isAuthenticated, setUser } = useAuthStore();
  const mounted = useMounted();
  const handleLogout = async () => {
    const res = await logout();
    if (res.success) {
      setUser(null);
      router.push('/');
    }
  };

  return (
    <header className="sticky top-0 z-50 w-full bg-background">
      <div className="container-padding mx-auto max-w-7xl">
        <div className="flex-between h-16">
          {/* Logo */}
          <Link
            href="/"
            className="flex items-center"
          >
            <Image
              src="/assets/images/hdcamp-logo-1.png"
              alt="HDCamp Logo"
              width={130}
              height={48}
              className="h-5 w-auto object-contain dark:brightness-0 dark:invert"
              priority
            />
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden items-center gap-6 md:flex">
            {navItems.map(item => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`relative py-2 text-sm font-bold transition-colors hover:text-primary ${isActive ? 'text-primary' : 'text-muted-foreground hover:text-foreground'
                    }`}
                >
                  {item.name}
                  {isActive && (
                    <span className="absolute bottom-0 left-0 right-0 h-0.5 rounded-full bg-primary" />
                  )}
                </Link>
              );
            })}
          </nav>

          {/* Desktop Actions */}
          <div className="hidden items-center gap-3 md:flex">
            {/* Theme toggle */}
            {/* <ModeToggle /> */}
            {/* Language Translator */}
            <GoogleTranslator />
            {/* Shopping Cart
            <Button
              onClick={() => router.push('/cart')}
              variant="ghost"
              size="icon"
              className="relative cursor-pointer"
            >
              <ShoppingCart className="h-5 w-5" />
              {cartCount > 0 && (
                <span className="bg-primary flex-center absolute -top-1 -right-1 h-5 w-5 rounded-full text-xs text-white">
                  {cartCount > 99 ? '99+' : cartCount}
                </span>
              )}
            </Button> */}

            {/* User Menu */}
            {mounted && isAuthenticated && user ? (
              <div className="flex items-center gap-2">
                {user.role === 'admin' && (
                  <Button
                    asChild
                    variant="outline"
                    className="cursor-pointer"
                    size="sm"
                  >
                    <Link href="/admin">
                      {/* <LayoutDashboard className="mr-2 h-4 w-4" /> */}
                      Admin
                    </Link>
                  </Button>
                )}
                {user.role === 'host' && (
                  <Button
                    asChild
                    variant="outline"
                    className="cursor-pointer"
                    size="sm"
                  >
                    <Link href="/host">
                      {/* <LayoutDashboard className="mr-2 h-4 w-4" /> */}
                      Trang Host
                    </Link>
                  </Button>
                )}
                {user.role === 'user' && (
                  <Button
                    asChild
                    variant="outline"
                    className="cursor-pointer"
                    size="sm"
                  >
                    <Link href="/become-host">
                      {/* <LayoutDashboard className="mr-2 h-4 w-4" /> */}
                      Trở thành Host
                    </Link>
                  </Button>
                )}
                {/* <Button
                  onClick={() => router.push('/cart')}
                  variant="ghost"
                  size="icon"
                  className="relative cursor-pointer"
                >
                  <ShoppingCart className="h-5 w-5" />
                  {cartCount > 0 && (
                    <span className="bg-primary flex-center absolute -top-1 -right-1 h-5 w-5 rounded-full text-xs text-white">
                      {cartCount > 99 ? '99+' : cartCount}
                    </span>
                  )}
                </Button> */}

                <div
                  onClick={() => router.push(`/u/${user.username}`)}
                  className="flex cursor-pointer items-center gap-2 rounded-md border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 px-3 py-2"
                >
                  <User className="h-4 w-4" />
                  {/* <span className="text-sm font-medium">{user.username}</span> */}
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleLogout}
                  title="Đăng xuất"
                >
                  <LogOut className="h-5 w-5" />
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Button asChild variant="ghost" size="sm">
                  <Link href="/sign-in">Đăng nhập</Link>
                </Button>
                <Button asChild size="sm">
                  <Link href="/sign-up">Đăng ký</Link>
                </Button>
              </div>
            )}
          </div>

          {/* Mobile Actions */}
          <div className="flex items-center gap-2 md:hidden">
            <GoogleTranslator />
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="border-t bg-background md:hidden">
          <nav className="container-padding mx-auto max-w-7xl space-y-1 py-4">
            {navItems.map(item => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`block rounded-md px-3 py-2 text-base font-medium transition-colors ${isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-foreground/60 hover:text-primary hover:bg-accent'
                    }`}
                >
                  {item.name}
                </Link>
              );
            })}

            {/* Mobile Cart Button */}
            <button
              onClick={() => {
                router.push('/cart');
                setMobileMenuOpen(false);
              }}
              className="text-foreground/60 hover:text-primary flex w-full items-center justify-between rounded-md px-3 py-2 text-base font-medium hover:bg-accent"
            >
              {/* <span className="flex items-center gap-2">
                <ShoppingCart className="h-5 w-5" />
                Giỏ hàng
              </span>
              {cartCount > 0 && (
                <span className="bg-primary flex h-6 w-6 items-center justify-center rounded-full text-xs text-white">
                  {cartCount > 99 ? '99+' : cartCount}
                </span>
              )} */}
            </button>

            <div className="border-t pt-4">
              {mounted && isAuthenticated && user ? (
                <div className="space-y-2">
                  {user.role === 'admin' && (
                    <Button
                      asChild
                      variant="outline"
                      className="w-full justify-start"
                    >
                      <Link
                        href="/admin"
                        onClick={() => setMobileMenuOpen(false)}
                      >
                        <LayoutDashboard className="mr-2 h-4 w-4" />
                        Admin Panel
                      </Link>
                    </Button>
                  )}
                  {user.role === 'host' && (
                    <Button
                      asChild
                      variant="outline"
                      className="w-full justify-start"
                    >
                      <Link
                        href="/host"
                        onClick={() => setMobileMenuOpen(false)}
                      >
                        <LayoutDashboard className="mr-2 h-4 w-4" />
                        Host Panel
                      </Link>
                    </Button>
                  )}
                  <div className="flex items-center gap-2 rounded-md border px-3 py-2">
                    <User className="h-4 w-4" />
                    <span className="text-sm font-medium">{user.username}</span>
                  </div>
                  <Button
                    variant="outline"
                    className="w-full justify-start"
                    onClick={handleLogout}
                  >
                    <LogOut className="mr-2 h-4 w-4" />
                    Đăng xuất
                  </Button>
                </div>
              ) : (
                <div className="space-y-2">
                  <Button asChild variant="outline" className="w-full">
                    <Link
                      href="/sign-in"
                      onClick={() => setMobileMenuOpen(false)}
                    >
                      Đăng nhập
                    </Link>
                  </Button>
                  <Button asChild variant="outline" className="w-full">
                    <Link
                      href="/sign-up"
                      onClick={() => setMobileMenuOpen(false)}
                    >
                      Đăng ký
                    </Link>
                  </Button>
                </div>
              )}
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
