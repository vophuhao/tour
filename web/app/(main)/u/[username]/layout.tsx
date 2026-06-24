'use client';

import { useMounted } from '@/hooks/useMounted';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { getUserByUsername, getUserStats } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';
import {
  CheckCircle2,
  Eye,
  Heart,
  Loader2,
  MapPin,
  Settings,
  Compass,
  FileText,
  Tent,
  ShieldCheck,
} from 'lucide-react';
import Link from 'next/link';
import { useParams, usePathname } from 'next/navigation';

interface UserProfile {
  _id: string;
  username: string;
  email: string;
  avatarUrl?: string;
  bio?: string;
  location?: string;
  role: string;
  isVerified: boolean;
  createdAt: string;
}

export default function UserProfileLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const params = useParams();
  const pathname = usePathname();
  // Decode username to handle special characters and spaces
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();

  const { data, isLoading, error } = useQuery({
    queryKey: ['user', username],
    queryFn: () => getUserByUsername(username),
    enabled: !!username,
  });

  const { data: statsData } = useQuery({
    queryKey: ['user-stats', username],
    queryFn: () => getUserStats(username),
    enabled: !!username,
  });

  const mounted = useMounted();

  const profile = data?.data as UserProfile | undefined;
  const stats = statsData?.data as
    | { bookings: number; orders: number; reviews: number; saves?: number }
    | undefined;
  const isOwnProfile = currentUser?.username === username;

  // Determine active tab
  const getActiveTab = () => {
    if (pathname.includes('/saves')) return 'saves';
    if (pathname.includes('/reviews')) return 'reviews';
    if (pathname.includes('/posts')) return 'posts';
    if (pathname.includes('/spots')) return 'spots';
    return 'trips';
  };

  const activeTab = getActiveTab();

  if (isLoading || !mounted) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="text-primary mx-auto h-12 w-12 animate-spin" />
          <p className="text-muted-foreground mt-4">Đang tải...</p>
        </div>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <p className="text-red-600">Không tìm thấy người dùng</p>
            <Button asChild className="mt-4" variant="outline">
              <Link href="/">Về trang chủ</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const memberSince = format(new Date(profile.createdAt), 'MMMM yyyy', {
    locale: vi,
  });

  return (
    <div className="min-h-screen bg-slate-50/50 dark:bg-slate-950/20 text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-[1400px] px-6 py-8 sm:px-8 lg:px-12">
        <div className="grid gap-8 lg:grid-cols-4">
          {/* Left Sidebar - Profile Info - STICKY */}
          <div className="space-y-4 lg:col-span-1">
            <div className="space-y-4 lg:sticky lg:top-8">
              {/* Profile Card */}
              <Card className="border border-slate-200/80 dark:border-slate-850 hover:shadow-xs transition-shadow bg-white dark:bg-slate-900">
                <CardContent className="p-6 space-y-5">
                  {/* Avatar */}
                  <div className="flex flex-col items-center">
                    <div className="relative">
                      <Avatar className="h-24 w-24 ring-4 ring-primary/20">
                        <AvatarImage
                          src={profile.avatarUrl}
                          alt={profile.username}
                        />
                        <AvatarFallback className="bg-primary text-white text-2xl">
                          {profile.username?.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      {profile.isVerified && (
                        <div className="absolute right-0 bottom-0 rounded-full bg-white dark:bg-slate-950 p-1 border border-slate-200 dark:border-slate-800">
                          <CheckCircle2 className="h-4 w-4 text-primary" />
                        </div>
                      )}
                    </div>
                    <h1 className="mt-3 text-xl font-bold text-slate-900 dark:text-white">
                      {profile.username}
                    </h1>
                    {profile.role === 'host' && (
                      <Badge className="mt-2 border-0 bg-primary text-xs text-white">
                        Chủ nhà
                      </Badge>
                    )}
                  </div>

                  <Separator />

                  {/* Member Info */}
                  <div className="space-y-3.5 text-sm">
                    <div className="flex items-center gap-2.5 text-slate-600 dark:text-slate-400">
                      <Heart className="h-4 w-4 flex-shrink-0 text-rose-500" />
                      <span className="text-xs">Camper từ {memberSince}</span>
                    </div>
                    {profile.location && (
                      <div className="flex items-center gap-2.5 text-slate-600 dark:text-slate-400">
                        <MapPin className="h-4 w-4 flex-shrink-0 text-primary" />
                        <span className="text-xs">{profile.location}</span>
                      </div>
                    )}
                  </div>

                  {/* Bio */}
                  <div className="text-xs leading-relaxed text-slate-650 dark:text-slate-400">
                    {profile.bio ? (
                      <p>{profile.bio}</p>
                    ) : (
                      <p className="text-slate-450 italic">Chưa có giới thiệu</p>
                    )}
                  </div>

                  <Separator />

                  {/* Trust Status info directly integrated */}
                  <div className="space-y-2.5">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Đáng tin cậy</span>
                    <div className="flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300">
                      <CheckCircle2 className="h-4 w-4 text-primary shrink-0" />
                      <span>Email đã xác thực</span>
                    </div>
                    {!profile.isVerified && isOwnProfile && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full text-xs cursor-pointer border border-primary/20 hover:bg-primary/5 text-primary py-1"
                      >
                        Xác thực email ngay
                      </Button>
                    )}
                  </div>

                  <Separator />

                  {/* Actions */}
                  <div className="space-y-2">
                    {isOwnProfile && (
                      <Button
                        asChild
                        variant="outline"
                        size="sm"
                        className="w-full border border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
                      >
                        <Link href="/u/edit">
                          <Settings className="mr-2 h-3.5 w-3.5 text-primary" />
                          <span className="text-xs">Quản lý tài khoản</span>
                        </Link>
                      </Button>
                    )}

                    <Button
                      variant="ghost"
                      size="sm"
                      className="w-full text-slate-600 dark:text-slate-450 hover:text-slate-900 dark:hover:text-white cursor-pointer"
                    >
                      <Eye className="mr-2 h-3.5 w-3.5 text-primary" />
                      <span className="text-xs">Xem trên bản đồ</span>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Balance Card */}
          {/* {isOwnProfile && (
                <Card className="border-primary/20 bg-primary/5 shadow-md">
                  <CardContent className="p-4">
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-xl font-bold text-slate-900 dark:text-white">
                            0₫
                          </div>
                          <div className="text-xs text-slate-500">Số dư</div>
                        </div>
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/20">
                          <span className="text-xl">💰</span>
                        </div>
                      </div>
                      <Button
                        variant="link"
                        className="h-auto justify-start p-0 text-xs text-primary hover:text-primary-dark"
                      >
                        → Nhận điểm thưởng
                      </Button>
                    </div>
                  </CardContent>
                </Card>


      {/* Right Content Area */}
      <div className="lg:col-span-3">
        {/* Stats Bar redesigned as tabs */}
        <div className="mb-8 border-b border-slate-200 dark:border-slate-800">
          <div className="flex gap-6 overflow-x-auto pb-px scrollbar-none">
            <Link
              href={`/u/${username}/trips`}
              className={`flex items-center gap-2 pb-4 text-xs font-bold border-b-2 transition-all shrink-0 ${activeTab === 'trips'
                ? 'border-primary text-primary'
                : 'border-transparent text-slate-500 hover:text-slate-850 dark:hover:text-white'
                }`}
            >
              <Compass className="h-4 w-4" />
              <span>Chuyến đi</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${activeTab === 'trips' ? 'bg-primary/10 text-primary' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                {stats?.bookings ?? 0}
              </span>
            </Link>
            <Link
              href={`/u/${username}/saves`}
              className={`flex items-center gap-2 pb-4 text-xs font-bold border-b-2 transition-all shrink-0 ${activeTab === 'saves'
                ? 'border-primary text-primary'
                : 'border-transparent text-slate-500 hover:text-slate-850 dark:hover:text-white'
                }`}
            >
              <Heart className="h-4 w-4" />
              <span>Đã lưu</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${activeTab === 'saves' ? 'bg-primary/10 text-primary' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                {stats?.saves ?? 0}
              </span>
            </Link>

            {/* Bài viết diễn đàn */}
            {isOwnProfile && (
              <Link
                href={`/u/${username}/posts`}
                className={`flex items-center gap-2 pb-4 text-xs font-bold border-b-2 transition-all shrink-0 ${activeTab === 'posts'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-slate-500 hover:text-slate-850 dark:hover:text-white'
                  }`}
              >
                <FileText className="h-4 w-4" />
                <span>Bài viết</span>
              </Link>
            )}

            {/* Địa điểm chia sẻ */}
            {isOwnProfile && (
              <Link
                href={`/u/${username}/spots`}
                className={`flex items-center gap-2 pb-4 text-xs font-bold border-b-2 transition-all shrink-0 ${activeTab === 'spots'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-slate-500 hover:text-slate-850 dark:hover:text-white'
                  }`}
              >
                <Tent className="h-4 w-4" />
                <span>Địa điểm</span>
              </Link>
            )}
          </div>
        </div>

        {/* Tab Content */}
        <div className="min-h-[400px]">{children}</div>
      </div>
    </div>
  </div>
</div>

  );
}
