'use client';

import { useEffect, useState } from 'react';
import { Trophy, Star, MessageSquare, Calendar, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';

interface SuperhostWidgetProps {
  stats: any;
}

const API = process.env.NEXT_PUBLIC_API_URL;

export function SuperhostWidget({ stats }: SuperhostWidgetProps) {
  const [loading, setLoading] = useState(true);
  const [superhostData, setSuperhostData] = useState<any>(null);

  useEffect(() => {
    async function fetchSuperhostStatus() {
      try {
        const token = localStorage.getItem('accessToken');
        // Let's call the superhost-status API. Since host might have multiple properties, 
        // we can fetch from the host properties, or get dashboard details.
        // To be safe and clean, let's call a general/property specific endpoint, or evaluate based on backend status.
        // Let's list host properties first to find one property ID, or call property superhost-status.
        // For simplicity and effectiveness, we will fetch properties of this host.
        const resProperties = await fetch(`${API}/properties/my/list`, {
          credentials: 'include',
          headers: { Authorization: `Bearer ${token}` },
        });
        if (resProperties.ok) {
          const propsData = await resProperties.json();
          const list = Array.isArray(propsData.data) ? propsData.data : (propsData.data?.properties || []);
          const firstProperty = list[0];
          if (firstProperty) {
            const resStatus = await fetch(`${API}/properties/${firstProperty._id}/superhost-status`, {
              credentials: 'include',
              headers: { Authorization: `Bearer ${token}` },
            });
            if (resStatus.ok) {
              const statusData = await resStatus.json();
              setSuperhostData(statusData.data);
            }
          }
        }
      } catch (err) {
        console.error('Error fetching superhost status:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchSuperhostStatus();
  }, []);

  if (loading) {
    return (
      <Card className="relative overflow-hidden border border-slate-200/80 dark:border-slate-850">
        <CardContent className="p-6 flex items-center justify-center h-48">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-indigo-600 border-t-transparent"></div>
        </CardContent>
      </Card>
    );
  }

  if (!superhostData) {
    return null;
  }

  const { criteria, isSuperhost, superhostSince } = superhostData;

  return (
    <Card className="relative overflow-hidden border border-amber-250 dark:border-amber-900/40 bg-gradient-to-r from-amber-50/30 to-yellow-50/30 dark:from-amber-950/5 dark:to-yellow-950/5">
      <div className="absolute top-0 left-0 w-full h-[4px] bg-gradient-to-r from-amber-400 via-yellow-500 to-amber-600" />
      <CardHeader className="pb-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-amber-100 dark:bg-amber-950/60 p-2.5 shadow-sm text-amber-650">
              <Trophy className="h-6 w-6" />
            </div>
            <div>
              <CardTitle className="text-lg font-bold text-amber-900 dark:text-amber-300 flex items-center gap-2">
                Trạng thái Superhost
                {isSuperhost && (
                  <Badge className="bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs py-0.5">
                    Đạt điều kiện
                  </Badge>
                )}
              </CardTitle>
              <CardDescription className="text-slate-500 dark:text-slate-400 mt-0.5">
                {isSuperhost && superhostSince
                  ? `Bạn đã là Superhost từ ${format(new Date(superhostSince), 'MM/yyyy', { locale: vi })}`
                  : 'Hãy đạt các tiêu chí sau đây để nhận danh hiệu Superhost và gia tăng lượt hiển thị.'}
              </CardDescription>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2 lg:grid-cols-4 pt-3">
        {/* Rating Criterion */}
        <div className="space-y-2 p-4 rounded-xl border bg-white dark:bg-slate-900/50 border-slate-205 dark:border-slate-800">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-1.5 font-semibold text-slate-700 dark:text-slate-350">
              <Star className="h-4 w-4 text-amber-500 fill-amber-500" />
              Đánh giá trung bình
            </span>
            <span className="font-extrabold text-slate-900 dark:text-white">
              {criteria.rating.value} / {criteria.rating.required}
            </span>
          </div>
          <Progress value={Math.min((criteria.rating.value / criteria.rating.required) * 100, 100)} className="h-2 bg-slate-100" />
          <p className="text-[10px] font-medium text-slate-400 flex items-center gap-1">
            {criteria.rating.passed ? (
              <span className="text-green-600 font-bold">✓ Đạt yêu cầu</span>
            ) : (
              <span className="text-red-500 font-semibold">✗ Cần tối thiểu {criteria.rating.required}</span>
            )}
          </p>
        </div>

        {/* Response Rate Criterion */}
        <div className="space-y-2 p-4 rounded-xl border bg-white dark:bg-slate-900/50 border-slate-205 dark:border-slate-800">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-1.5 font-semibold text-slate-700 dark:text-slate-350">
              <MessageSquare className="h-4 w-4 text-indigo-500" />
              Tỷ lệ phản hồi
            </span>
            <span className="font-extrabold text-slate-900 dark:text-white">
              {criteria.responseRate.value}% / {criteria.responseRate.required}%
            </span>
          </div>
          <Progress value={criteria.responseRate.value} className="h-2 bg-slate-100" />
          <p className="text-[10px] font-medium text-slate-400 flex items-center gap-1">
            {criteria.responseRate.passed ? (
              <span className="text-green-600 font-bold">✓ Đạt yêu cầu</span>
            ) : (
              <span className="text-red-500 font-semibold">✗ Cần tối thiểu {criteria.responseRate.required}%</span>
            )}
          </p>
        </div>

        {/* Completed Bookings Criterion */}
        <div className="space-y-2 p-4 rounded-xl border bg-white dark:bg-slate-900/50 border-slate-205 dark:border-slate-800">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-1.5 font-semibold text-slate-700 dark:text-slate-350">
              <Calendar className="h-4 w-4 text-emerald-500" />
              Booking hoàn thành
            </span>
            <span className="font-extrabold text-slate-900 dark:text-white">
              {criteria.completedBookings.value} / {criteria.completedBookings.required}
            </span>
          </div>
          <Progress value={Math.min((criteria.completedBookings.value / criteria.completedBookings.required) * 100, 100)} className="h-2 bg-slate-100" />
          <p className="text-[10px] font-medium text-slate-400 flex items-center gap-1">
            {criteria.completedBookings.passed ? (
              <span className="text-green-600 font-bold">✓ Đạt yêu cầu</span>
            ) : (
              <span className="text-red-500 font-semibold">✗ Cần thêm {criteria.completedBookings.required - criteria.completedBookings.value} bookings</span>
            )}
          </p>
        </div>

        {/* No Cancellations Criterion */}
        <div className="space-y-2 p-4 rounded-xl border bg-white dark:bg-slate-900/50 border-slate-205 dark:border-slate-800">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-1.5 font-semibold text-slate-700 dark:text-slate-350">
              <ShieldAlert className="h-4 w-4 text-rose-500" />
              Không tự ý hủy đặt phòng
            </span>
            <span className="font-extrabold text-slate-900 dark:text-white">
              {criteria.noHostCancellations.value ? '0 lần' : 'Có hủy'}
            </span>
          </div>
          <Progress value={criteria.noHostCancellations.value ? 100 : 0} className="h-2 bg-slate-100" />
          <p className="text-[10px] font-medium text-slate-400 flex items-center gap-1">
            {criteria.noHostCancellations.passed ? (
              <span className="text-green-600 font-bold">✓ Đạt yêu cầu (Không hủy)</span>
            ) : (
              <span className="text-red-500 font-semibold">✗ Vi phạm điều kiện (Có hủy booking)</span>
            )}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
