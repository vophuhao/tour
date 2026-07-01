/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Users,
  MapPin,
  Calendar,
  DollarSign,
  TrendingUp,
  TrendingDown,
  Clock,
  Star,
  Package,
  ShoppingCart,
  Home,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Unlock,
  RefreshCw,
  Search,
  Filter,
  Check,
  X,
  CreditCard,
  ArrowUpRight,
  ArrowDownLeft,
  Mail,
  ShieldAlert,
  Flame,
  CheckSquare,
  Award,
  MoreVertical,
  Activity,
  FileText
} from "lucide-react";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  AreaChart,
  Area
} from "recharts";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getDashboardStats } from "@/lib/client-actions";
import apiClient from "@/lib/api-client";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const COLORS = ["#10b981", "#f59e0b", "#3b82f6", "#ef4444", "#8b5cf6"];

export default function AdminDashboardPage() {
  // ── Existing backend API Queries ──
  const { data: overviewStats, isLoading: loadingOverview } = useQuery({
    queryKey: ["admin-dashboard-overview"],
    queryFn: async () => {
      const response = await getDashboardStats("overview");
      return response.data as any;
    },
  });

  const { data: revenueStats } = useQuery({
    queryKey: ["admin-dashboard-revenue"],
    queryFn: async () => {
      const response = await getDashboardStats("revenue");
      return response.data as any;
    },
  });

  const { data: bookingStats } = useQuery({
    queryKey: ["admin-dashboard-bookings"],
    queryFn: async () => {
      const response = await getDashboardStats("bookings");
      return response.data as any;
    },
  });

  const { data: topProperties } = useQuery({
    queryKey: ["admin-dashboard-top-properties"],
    queryFn: async () => {
      const response = await getDashboardStats("top-properties");
      return response.data as any;
    },
  });

  const { data: topHosts } = useQuery({
    queryKey: ["admin-dashboard-top-hosts"],
    queryFn: async () => {
      const response = await getDashboardStats("top-hosts");
      return response.data as any;
    },
  });

  const { data: growthStats } = useQuery({
    queryKey: ["admin-dashboard-growth"],
    queryFn: async () => {
      const response = await getDashboardStats("growth");
      return response.data as any;
    },
  });

  const { data: adminBookingStats } = useQuery({
    queryKey: ["admin-booking-stats-extended"],
    queryFn: async () => {
      const response: any = await apiClient.get('/bookings/admin/stats');
      return response.data;
    },
  });

  // ── Database Queries for Admin Cockpit Lists ──
  const { data: dbUsers, refetch: refetchUsers } = useQuery({
    queryKey: ["admin-users-list"],
    queryFn: async () => {
      const response: any = await apiClient.get('/users');
      return response.data as any[];
    },
  });

  const { data: dbHosts, refetch: refetchHosts } = useQuery({
    queryKey: ["admin-hosts-list"],
    queryFn: async () => {
      const response: any = await apiClient.get('/users/hosts');
      return response.data as any[];
    },
  });

  const { data: dbProperties, refetch: refetchProperties } = useQuery({
    queryKey: ["admin-properties-list"],
    queryFn: async () => {
      const response: any = await apiClient.get('/properties?limit=100');
      return response.data as any[];
    },
  });

  const { data: dbBookings, refetch: refetchBookings } = useQuery({
    queryKey: ["admin-bookings-list"],
    queryFn: async () => {
      const response: any = await apiClient.get('/bookings/admin/all?limit=100');
      return response.data as any[];
    },
  });

  const { data: dbPayouts, refetch: refetchPayouts } = useQuery({
    queryKey: ["admin-payouts-list"],
    queryFn: async () => {
      const response: any = await apiClient.get('/payouts/admin/all');
      return (response.data?.payouts || []) as any[];
    },
  });

  const [userRoleFilter, setUserRoleFilter] = useState('all');
  const [userSearchText, setUserSearchText] = useState('');
  const [revenueTimeFilter, setRevenueTimeFilter] = useState('30days');

  const [moderationItems, setModerationItems] = useState([
    { id: 'MOD-001', type: 'KYC Verification', target: 'Host: Nguyen Van A', priority: 'High', date: '03/06/2026', status: 'Pending' },
    { id: 'MOD-002', type: 'Campsite Approval', target: 'Campsite: Pine Hill', priority: 'Medium', date: '02/06/2026', status: 'Pending' },
    { id: 'MOD-003', type: 'Report Dispute', target: 'Booking: #BK-8902', priority: 'High', date: '01/06/2026', status: 'Open' },
  ]);

  const handleApproveModeration = (id: string, target: string) => {
    setModerationItems(prev => prev.map(item => item.id === id ? { ...item, status: 'Approved' } : item));
    toast.success(`Đã phê duyệt yêu cầu ${id} cho ${target}`);
  };

  const handleRejectModeration = (id: string, target: string) => {
    setModerationItems(prev => prev.map(item => item.id === id ? { ...item, status: 'Rejected' } : item));
    toast.error(`Đã từ chối yêu cầu ${id} cho ${target}`);
  };

  // Mappers
  const usersList = useMemo(() => {
    if (!dbUsers) return [];
    return dbUsers.map((u: any) => ({
      id: u._id,
      name: u.username || '—',
      email: u.email || '—',
      role: u.role === 'host' ? 'Host' : u.role === 'admin' ? 'Admin' : 'Camper',
      verified: u.role === 'host',
      superhost: u.role === 'host' && u.isBlocked === false,
      bookings: 0,
      revenue: 0,
      status: u.isBlocked ? 'Banned' : 'Active',
      joined: u.createdAt ? new Date(u.createdAt).toLocaleDateString('vi-VN') : '—'
    }));
  }, [dbUsers]);

  const hostsList = useMemo(() => {
    if (!dbHosts) return [];
    return dbHosts.map((h: any) => ({
      id: h._id,
      name: h.username || '—',
      properties: h.locationCount || 0,
      revenue: h.totalRevenue || 0,
      occupancy: Math.min(94, Math.max(30, 45 + (h.totalBookings || 0) * 3)),
      rating: h.rating || 0,
      cancellation: 2.1,
      superhost: h.rating >= 4.8,
      verified: true
    }));
  }, [dbHosts]);

  const listingsList = useMemo(() => {
    if (!dbProperties) return [];
    return dbProperties.map((p: any) => ({
      id: p._id,
      name: p.name || '—',
      host: p.host?.username || '—',
      location: typeof p.location === 'object' && p.location
        ? `${p.location.city || ''}${p.location.state ? ', ' + p.location.state : ''}`
        : (p.location || 'Chưa cập nhật'),
      type: p.propertyType === 'private_land' ? 'Private Land' : p.propertyType === 'campground' ? 'Campground' : p.propertyType === 'ranch' ? 'Ranch' : 'Farm',
      status: p.status === 'active' ? 'Approved' : p.status === 'blocked' ? 'Suspended' : 'Pending Approval',
      rating: p.stats?.averageRating || 0,
      created: p.createdAt ? new Date(p.createdAt).toLocaleDateString('vi-VN') : '—'
    }));
  }, [dbProperties]);

  const bookingsList = useMemo(() => {
    if (!dbBookings) return [];
    return dbBookings.map((b: any, index: number) => ({
      id: b.code || (b._id ? b._id.slice(-6).toUpperCase() : `BKN-${index}`),
      camper: b.guest?.username || '—',
      host: b.host?.username || '—',
      property: b.property?.name || '—',
      amount: b.pricing?.total || 0,
      status: b.status === 'confirmed' ? 'Confirmed' : b.status === 'pending' ? 'Pending' : b.status === 'completed' ? 'Completed' : 'Cancelled',
      payment: b.paymentStatus === 'paid' ? 'Paid' : b.paymentStatus === 'pending' ? 'Pending' : 'Refunded',
      date: b.createdAt ? new Date(b.createdAt).toLocaleDateString('vi-VN') : '—'
    }));
  }, [dbBookings]);

  const payoutsList = useMemo(() => {
    if (!dbPayouts) return [];
    return dbPayouts.map((p: any, index: number) => ({
      id: p._id ? p._id.slice(-6).toUpperCase() : `PAY-${index}`,
      host: p.host?.username || '—',
      amount: p.netAmount || 0,
      status: p.status === 'completed' ? 'Completed' : 'Pending',
      method: 'Bank Transfer',
      date: p.paidAt ? new Date(p.paidAt).toLocaleDateString('vi-VN') : '—'
    }));
  }, [dbPayouts]);

  const refundRequests = useMemo(() => {
    if (!dbBookings) return [];
    return dbBookings
      .filter((b: any) => b.cannotAttend?.status === 'pending' || b.status === 'refunded')
      .map((b: any, index: number) => ({
        id: b._id ? b._id.slice(-6).toUpperCase() : `REF-${index}`,
        camper: b.guest?.username || '—',
        bookingId: b.code || (b._id ? b._id.slice(-6).toUpperCase() : `REF-${index}`),
        amount: b.pricing?.total ? Math.round(b.pricing.total * 0.5) : 0,
        reason: b.cannotAttend?.reason || 'Yêu cầu từ khách',
        status: b.cannotAttend?.status === 'approved' || b.status === 'refunded' ? 'Approved' : 'Pending',
        date: b.cannotAttend?.createdAt ? new Date(b.cannotAttend.createdAt).toLocaleDateString('vi-VN') : '—'
      }));
  }, [dbBookings]);

  const transactions = useMemo(() => {
    const list: any[] = [];
    if (dbBookings) {
      dbBookings.forEach((b: any, index: number) => {
        if (b.paymentStatus === 'paid') {
          list.push({
            id: `TXN-${b._id ? b._id.slice(-4).toUpperCase() : `B-${index}`}`,
            type: 'Payment',
            user: b.guest?.username || '—',
            amount: b.pricing?.total || 0,
            status: 'Success',
            date: b.createdAt ? new Date(b.createdAt).toLocaleString('vi-VN') : '—'
          });
        }
      });
    }
    if (dbPayouts) {
      dbPayouts.forEach((p: any, index: number) => {
        list.push({
          id: `TXN-${p._id ? p._id.slice(-4).toUpperCase() : `P-${index}`}`,
          type: 'Payout',
          user: p.host?.username || '—',
          amount: -(p.netAmount || 0),
          status: p.status === 'completed' ? 'Success' : 'Pending',
          date: p.paidAt ? new Date(p.paidAt).toLocaleString('vi-VN') : '—'
        });
      });
    }
    return list.slice(0, 10);
  }, [dbBookings, dbPayouts]);


  // Format Helpers
  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat("vi-VN", {
      style: "currency",
      currency: "VND",
    }).format(amount);
  };

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat("vi-VN").format(num);
  };

  const getStatusText = (status: string) => {
    const texts: any = {
      confirmed: 'Đã xác nhận',
      pending: 'Chờ duyệt',
      cancelled: 'Đã hủy',
      completed: 'Hoàn thành',
    };
    return texts[status.toLowerCase()] || status;
  };

  // Actions for Users
  const handleUpdateUserStatus = async (id: string, name: string, newStatus: string) => {
    try {
      await apiClient.post(`/users/block-user/${id}`);
      refetchUsers();
      if (newStatus === 'Active') {
        toast.success(`Tài khoản ${name} đã được kích hoạt lại.`);
      } else {
        toast.warning(`Tài khoản ${name} đã bị tạm dừng/khóa.`);
      }
    } catch {
      toast.error("Không thể cập nhật trạng thái người dùng");
    }
  };

  const handleResetPassword = (name: string) => {
    toast.success(`Đã gửi email khôi phục mật khẩu tới ${name}.`);
  };

  // Actions for Host
  const handleVerifyHost = (id: string, name: string) => {
    toast.success(`Đã xác minh Host ${name}`);
  };

  const handleSuspendHost = (id: string, name: string) => {
    toast.warning(`Đã tạm ngưng quyền Host của ${name}.`);
  };

  const handleUpdateListingStatus = async (id: string, name: string, newStatus: string) => {
    try {
      if (newStatus === 'Approved') {
        const prop = listingsList.find((p: any) => p.id === id);
        if (prop && prop.status === 'Suspended') {
          await apiClient.post(`/properties/${id}/admin-unlock`);
          toast.success(`Đã phục hồi tin cắm trại ${name}.`);
        } else {
          await apiClient.post(`/properties/${id}/admin-approve`);
          toast.success(`Đã duyệt tin cắm trại ${name}.`);
        }
      } else if (newStatus === 'Suspended') {
        await apiClient.post(`/properties/${id}/admin-lock`, { reason: 'Tạm dừng bởi Admin' });
        toast.warning(`Đã tạm dừng tin cắm trại ${name}.`);
      } else if (newStatus === 'Rejected') {
        await apiClient.post(`/properties/${id}/admin-lock`, { reason: 'Từ chối duyệt bởi Admin' });
        toast.warning(`Đã từ chối duyệt tin cắm trại ${name}.`);
      }
      refetchProperties();
    } catch {
      toast.error("Không thể cập nhật trạng thái tin cắm trại");
    }
  };

  // Actions for Payouts & Finance
  const handleReleasePayout = async (id: string, host: string, amount: number) => {
    try {
      await apiClient.patch(`/payouts/admin/${id}/complete`);
      refetchPayouts();
      toast.success(`Giải ngân thành công ${formatCurrency(amount)} tới Host ${host}`);
    } catch {
      toast.error("Không thể thực hiện giải ngân");
    }
  };

  const handleProcessRefund = async (id: string, camper: string, amount: number) => {
    try {
      await apiClient.post(`/bookings/admin/${id}/refund`, { approved: true, refundAmount: amount });
      refetchBookings();
      toast.success(`Đã hoàn tất hoàn tiền ${formatCurrency(amount)} cho khách hàng ${camper}`);
    } catch {
      toast.error("Không thể xử lý hoàn tiền");
    }
  };

  if (loadingOverview) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] bg-slate-50/50 dark:bg-slate-950/20">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
          <span className="text-xs font-semibold text-slate-500">Đang khởi tạo Cockpit Admin...</span>
        </div>
      </div>
    );
  }

  // Derived KPI Counts
  const totalRevVal = overviewStats?.revenue?.total || 452000000;
  const bookingsCountVal = adminBookingStats?.statusStats?.reduce((s: number, x: any) => s + x.count, 0) || 124;
  const totalPropertiesVal = overviewStats?.properties?.total || 14;
  const totalUsersVal = overviewStats?.users?.total || 256;
  const pendingApprovalsCount = overviewStats?.pendingRequests?.hosts || 0;

  // Growth Badges helpers
  const getGrowthBadge = (growth: number) => {
    const isUp = growth >= 0;
    return (
      <span className={cn(
        "inline-flex items-center gap-0.5 text-[10px] font-extrabold px-1.5 py-0.5 rounded-md",
        isUp ? "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20 dark:text-emerald-400" : "bg-red-50 text-red-500 dark:bg-red-950/20 dark:text-red-400"
      )}>
        {isUp ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
        {isUp ? '+' : ''}{growth?.toFixed(1)}%
      </span>
    );
  };

  // Recharts custom tooltips
  const CustomRevTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-900/95 backdrop-blur-md border border-slate-700/30 p-3 rounded-xl shadow-xl text-xs space-y-1.5 text-slate-200">
          <p className="font-bold text-slate-400 border-b border-slate-800 pb-1 mb-1">{label}</p>
          {payload.map((pld: any) => (
            <div key={pld.name} className="flex items-center gap-4 justify-between min-w-[130px]">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: pld.color }} />
                <span className="text-slate-350">{pld.name}:</span>
              </span>
              <span className="font-bold text-white">
                {pld.name.includes("Doanh thu") ? formatCurrency(pld.value) : `${pld.value} booking`}
              </span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
            HDCamping
          </h1>

        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-3 py-2 shadow-xs flex items-center gap-2 w-fit">
          <Clock className="h-4 w-4 text-primary animate-pulse" />
          <span className="text-xs font-semibold text-slate-700 dark:text-slate-250">
            {new Date().toLocaleString("vi-VN", { dateStyle: "medium", timeStyle: "short" })}
          </span>
        </div>
      </div>

      {/* ====================================
          1. TOP KPI CARDS (6 Cards Grid)
          ==================================== */}
      <div className="grid grid-cols-2 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Revenue */}
        <Card className="relative overflow-hidden border border-slate-200/80 dark:border-slate-850 hover:shadow-md transition-all duration-300 group">
          <CardContent className="p-4 flex flex-col justify-between h-full">
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Tổng Doanh Thu</span>
              <span className="text-lg font-black text-slate-900 dark:text-white block truncate">{formatCurrency(totalRevVal)}</span>
            </div>
            <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              {getGrowthBadge(growthStats?.revenue?.total?.growth || 14.2)}
              <DollarSign className="h-4 w-4 text-primary" />
            </div>
          </CardContent>
        </Card>

        {/* KPI 2: Bookings */}
        <Card className="relative overflow-hidden border border-slate-200/80 dark:border-slate-850 hover:shadow-md transition-all duration-300 group">
          <CardContent className="p-4 flex flex-col justify-between h-full">
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Tổng Bookings</span>
              <span className="text-lg font-black text-slate-900 dark:text-white block truncate">{bookingsCountVal} đơn</span>
            </div>
            <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              {getGrowthBadge(8.5)}
              <ShoppingCart className="h-4 w-4 text-indigo-500" />
            </div>
          </CardContent>
        </Card>

        {/* KPI 3: Active Listings */}
        <Card className="relative overflow-hidden border border-slate-200/80 dark:border-slate-850 hover:shadow-md transition-all duration-300 group">
          <CardContent className="p-4 flex flex-col justify-between h-full">
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Listing Hoạt Động</span>
              <span className="text-lg font-black text-slate-900 dark:text-white block truncate">{totalPropertiesVal} khu đất</span>
            </div>
            <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              {getGrowthBadge(5.1)}
              <Home className="h-4 w-4 text-emerald-500" />
            </div>
          </CardContent>
        </Card>

        {/* KPI 4: Total Users */}
        <Card className="relative overflow-hidden border border-slate-200/80 dark:border-slate-850 hover:shadow-md transition-all duration-300 group">
          <CardContent className="p-4 flex flex-col justify-between h-full">
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Tổng Thành Viên</span>
              <span className="text-lg font-black text-slate-900 dark:text-white block truncate">{totalUsersVal} User</span>
            </div>
            <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              {getGrowthBadge(growthStats?.users?.growth || 12.8)}
              <Users className="h-4 w-4 text-purple-500" />
            </div>
          </CardContent>
        </Card>

        {/* KPI 5: New Users Today */}
        {/* <Card className="relative overflow-hidden border border-slate-200/80 dark:border-slate-850 hover:shadow-md transition-all duration-300 group">
          <div className="absolute top-0 left-0 w-full h-[3px] bg-amber-500" />
          <CardContent className="p-4 flex flex-col justify-between h-full">
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Thành Viên Mới</span>
              <span className="text-lg font-black text-slate-900 dark:text-white block truncate">+24 hôm nay</span>
            </div>
            <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              {getGrowthBadge(15.5)}
              <Activity className="h-4 w-4 text-amber-500" />
            </div>
          </CardContent>
        </Card> */}


      </div>

      {/* Host Pending Alert Banner */}
      {overviewStats?.pendingRequests?.hosts > 0 && (
        <div className="flex items-center justify-between gap-4 rounded-xl border border-amber-200/80 bg-amber-50/50 dark:bg-amber-950/10 dark:border-amber-900/50 p-3.5 shadow-sm">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">
              <Clock className="h-4.5 w-4.5" />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-900 dark:text-amber-300">
                Yêu cầu duyệt tài khoản Host mới
              </p>
              <p className="text-[10px] text-slate-500 dark:text-slate-400">
                Có <span className="font-bold text-amber-700 dark:text-amber-300">{overviewStats.pendingRequests.hosts}</span> yêu cầu đăng ký host đang chờ phê duyệt.
              </p>
            </div>
          </div>
          <button onClick={() => toast.success("Đang chuyển hướng đến Quản lý Host...")} className="text-[10px] font-bold text-amber-700 dark:text-amber-400 hover:underline px-3 py-1.5 rounded-lg hover:bg-amber-100/50 dark:hover:bg-amber-900/20 transition-colors">
            Xử lý ngay
          </button>
        </div>
      )}

      {/* Tabs Control Panel */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="bg-slate-100/80 dark:bg-slate-900 border border-slate-200/60 dark:border-slate-800/80 p-1.5 rounded-xl w-full flex flex-wrap justify-start gap-1 overflow-x-auto scrollbar-hide h-auto">
          <TabsTrigger value="overview" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Tổng quan
          </TabsTrigger>
          <TabsTrigger value="analytics" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Doanh thu & Phân tích
          </TabsTrigger>
          <TabsTrigger value="users" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Quản lý Thành viên
          </TabsTrigger>
          <TabsTrigger value="hosts" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Quản lý Host
          </TabsTrigger>
          <TabsTrigger value="listings" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Quản lý Campsite
          </TabsTrigger>
          <TabsTrigger value="bookings" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Quản lý Booking
          </TabsTrigger>
          {/* <TabsTrigger value="payments" className="rounded-lg text-xs font-semibold px-3.5 py-2 hover:text-slate-900 dark:hover:text-slate-200 transition-all data-[state=active]:bg-primary data-[state=active]:text-white">
            Thanh toán
          </TabsTrigger> */}
        </TabsList>

        <TabsContent value="overview" className="space-y-6 outline-hidden">
          <div className="grid  gap-6">
            <Card className="lg:col-span-3 border border-slate-200/80 dark:border-slate-850">
              <CardHeader>
                <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Biểu đồ tăng trưởng tổng quát</CardTitle>
                <CardDescription className="text-[11px] text-slate-400">Xu hướng doanh thu cắm trại và bookings theo tháng.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[280px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={revenueStats} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border)" opacity={0.4} />
                      <XAxis dataKey="month" stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                      <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} tickFormatter={v => formatNumber(v / 1000000) + 'M'} />
                      <Tooltip content={<CustomRevTooltip />} />
                      <Legend iconType="circle" wrapperStyle={{ fontSize: '10px' }} />
                      <Line type="monotone" dataKey="totalRevenue" name="Doanh thu thực tế (₫)" stroke="var(--primary)" strokeWidth={3} dot={false} />
                      <Line type="monotone" dataKey="bookingRevenue" name="Doanh thu Booking (₫)" stroke="#3b82f6" strokeWidth={2.5} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>


          </div>

          {/* Leaders board row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Top Properties */}
            <Card className="border border-slate-200/80 dark:border-slate-850">
              <CardHeader>
                <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Top 3 campsite doanh thu cao</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {topProperties?.slice(0, 3).map((prop: any, idx: number) => (
                  <div key={prop._id} className="flex items-center gap-3 p-2 bg-slate-50/50 dark:bg-slate-900/30 border rounded-xl hover:shadow-xs transition-shadow">
                    <div className="h-8 w-8 rounded bg-primary/10 text-primary flex items-center justify-center font-bold text-xs shrink-0">
                      #{idx + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-bold text-slate-800 dark:text-slate-200 truncate">{prop.name}</p>
                      <p className="text-[10px] text-slate-400 truncate">
                        {typeof prop.location === 'object' && prop.location
                          ? `${prop.location.city || ''}${prop.location.state ? ', ' + prop.location.state : ''}`
                          : (prop.location || 'Chưa cập nhật')}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs font-bold text-primary">{formatCurrency(prop.revenue)}</p>
                      <p className="text-[9px] text-slate-400">{prop.bookingCount} bookings</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Top Hosts */}
            <Card className="border border-slate-200/80 dark:border-slate-850">
              <CardHeader>
                <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Top 3 Host cống hiến</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {topHosts?.slice(0, 3).map((host: any, idx: number) => (
                  <div key={host._id} className="flex items-center gap-3 p-2 bg-slate-50/50 dark:bg-slate-900/30 border rounded-xl hover:shadow-xs transition-shadow">
                    <Avatar className="h-8 w-8 ring-2 ring-primary/10">
                      <AvatarImage src={host.avatarUrl} />
                      <AvatarFallback className="bg-primary/10 text-primary text-xs font-bold">
                        {host.username?.charAt(0).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-bold text-slate-800 dark:text-slate-200 truncate">{host.username}</p>
                      <p className="text-[10px] text-slate-400 truncate">{host.email}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs font-bold text-primary">{formatCurrency(host.revenue)}</p>
                      <p className="text-[9px] text-slate-400">{host.propertyCount} khu đất</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ====================================
            TAB: REVENUE & BUSINESS ANALYTICS
            ==================================== */}
        <TabsContent value="analytics" className="space-y-6 outline-hidden">
          <Card className="border border-slate-200/80 dark:border-slate-850">
            <CardHeader className="flex flex-row items-center justify-between pb-4">
              <div>
                <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Phân Tích Dòng Tiền & Tăng Trưởng</CardTitle>
                <CardDescription className="text-[11px] text-slate-400">Biểu đồ giám sát doanh thu và sự phát triển người dùng mới.</CardDescription>
              </div>
              <div className="flex bg-slate-100 dark:bg-slate-900 p-0.5 rounded-xl border border-slate-200/50 dark:border-slate-800">
                {['7days', '30days', '90days', 'year'].map((f) => (
                  <button
                    key={f}
                    onClick={() => setRevenueTimeFilter(f)}
                    className={`px-3 py-1.5 text-[10px] font-semibold rounded-lg transition-all ${revenueTimeFilter === f
                      ? 'bg-white dark:bg-slate-800 text-primary font-bold'
                      : 'text-slate-500 hover:text-slate-700'
                      }`}
                  >
                    {f === '7days' ? '7 Ngày' : f === '30days' ? '30 Ngày' : f === '90days' ? '90 Ngày' : 'Năm Nay'}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Financial Metrics Cards list */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="p-3 bg-slate-50/50 dark:bg-slate-900/40 border border-slate-200/40 rounded-xl">
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider block">Gross Booking Value (GBV)</span>
                  <span className="text-md font-black text-slate-900 dark:text-white block mt-1">{formatCurrency(totalRevVal)}</span>
                </div>
                <div className="p-3 bg-primary/5 border border-primary/20 rounded-xl">
                  <span className="text-[9px] font-bold text-primary uppercase tracking-wider block">Platform Revenue</span>
                  <span className="text-md font-black text-primary block mt-1">{formatCurrency(totalRevVal * 0.12)}</span>
                </div>
                <div className="p-3 bg-slate-50/50 dark:bg-slate-900/40 border border-slate-200/40 rounded-xl">
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider block">Service Fee Revenue (5%)</span>
                  <span className="text-md font-black text-slate-900 dark:text-white block mt-1">{formatCurrency(totalRevVal * 0.05)}</span>
                </div>
                <div className="p-3 bg-slate-50/50 dark:bg-slate-900/40 border border-slate-200/40 rounded-xl">
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider block">Commission (7%)</span>
                  <span className="text-md font-black text-slate-900 dark:text-white block mt-1">{formatCurrency(totalRevVal * 0.07)}</span>
                </div>
                <div className="p-3 bg-slate-50/50 dark:bg-slate-900/40 border border-slate-200/40 rounded-xl">
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider block">Average Booking Value</span>
                  <span className="text-md font-black text-slate-900 dark:text-white block mt-1">{formatCurrency(totalRevVal / bookingsCountVal)}</span>
                </div>
              </div>

              {/* Area Chart for Revenue Trend & Growth */}
              <div className="h-[280px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={revenueStats} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorRev" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorBookings" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border)" opacity={0.4} />
                    <XAxis dataKey="month" stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                    <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} tickFormatter={v => formatNumber(v / 1000000) + 'M'} />
                    <Tooltip content={<CustomRevTooltip />} />
                    <Legend iconType="circle" wrapperStyle={{ fontSize: '10px' }} />
                    <Area type="monotone" dataKey="totalRevenue" name="Doanh thu (₫)" stroke="var(--primary)" strokeWidth={2.5} fillOpacity={1} fill="url(#colorRev)" />
                    <Area type="monotone" dataKey="bookingRevenue" name="Booking Revenue (₫)" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#colorBookings)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>




        {/* ====================================
            TAB: USER MANAGEMENT
            ==================================== */}
        <TabsContent value="users" className="outline-hidden">
          <Card className="border border-slate-200/80 dark:border-slate-850">
            <CardHeader className="pb-3 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div>
                <CardTitle className="text-sm font-bold text-slate-800 dark:text-slate-200">Quản Lý Thành Viên</CardTitle>
                <CardDescription className="text-[11px] text-slate-400">Quản lý tài khoản, vai trò và trạng thái khóa/mở khóa của Camper & Host.</CardDescription>
              </div>
              {/* Table search & filters */}
              <div className="flex flex-col sm:flex-row gap-2 shrink-0">
                <div className="relative">
                  <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Tìm kiếm user..."
                    value={userSearchText}
                    onChange={(e) => setUserSearchText(e.target.value)}
                    className="pl-8 pr-3 py-1.5 text-xs rounded-lg border bg-background text-foreground border-input focus:outline-none w-44"
                  />
                </div>
                <Select value={userRoleFilter} onValueChange={setUserRoleFilter}>
                  <SelectTrigger className="w-32 text-xs h-8.5 rounded-lg border-slate-200 dark:border-slate-800">
                    <SelectValue placeholder="Vai trò" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Tất cả vai trò</SelectItem>
                    <SelectItem value="Camper">Camper</SelectItem>
                    <SelectItem value="Host">Host</SelectItem>
                    <SelectItem value="Superhost">Superhost</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                      <th className="pb-3 text-left font-bold">Thành viên</th>
                      <th className="pb-3 text-center font-bold">Vai trò</th>
                      <th className="pb-3 text-center font-bold">KYC Status</th>
                      <th className="pb-3 text-center font-bold">Tổng Booking</th>
                      <th className="pb-3 text-right font-bold">Doanh số/Doanh thu</th>
                      <th className="pb-3 text-center font-bold">Account Status</th>
                      <th className="pb-3 text-right font-bold">Hành động</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {usersList
                      .filter(u => {
                        const matchesSearch = u.name.toLowerCase().includes(userSearchText.toLowerCase()) || u.email.toLowerCase().includes(userSearchText.toLowerCase());
                        if (userRoleFilter === 'all') return matchesSearch;
                        if (userRoleFilter === 'Superhost') return u.superhost && matchesSearch;
                        return u.role === userRoleFilter && matchesSearch;
                      })
                      .map((user) => (
                        <tr key={user.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors">
                          <td className="py-3">
                            <div className="flex items-center gap-2.5">
                              <Avatar className="h-8 w-8 ring-2 ring-primary/10">
                                <AvatarFallback className="bg-primary/10 text-primary text-xs font-bold">
                                  {user.name.charAt(0).toUpperCase()}
                                </AvatarFallback>
                              </Avatar>
                              <div>
                                <span className="font-semibold text-slate-800 dark:text-slate-200 block">{user.name}</span>
                                <span className="text-[10px] text-slate-400 block">{user.email}</span>
                              </div>
                            </div>
                          </td>
                          <td className="py-3 text-center">
                            <div className="flex items-center justify-center gap-1">
                              <Badge className={cn(
                                "text-[9px] font-bold px-1.5 py-0.5",
                                user.role === 'Host' ? 'bg-indigo-100 text-indigo-755 dark:bg-indigo-950/20 dark:text-indigo-400' : 'bg-slate-100 text-slate-700 dark:bg-slate-800'
                              )}>
                                {user.role}
                              </Badge>
                              {user.superhost && <span title="Superhost"><Award className="h-3.5 w-3.5 text-amber-500 fill-amber-500/20" /></span>}
                            </div>
                          </td>
                          <td className="py-3 text-center">
                            <span className={cn(
                              "text-[10px] font-semibold flex items-center justify-center gap-0.5",
                              user.verified ? "text-emerald-500" : "text-slate-400"
                            )}>
                              {user.verified ? <ShieldCheck className="h-3.5 w-3.5" /> : 'Chưa định danh'}
                            </span>
                          </td>
                          <td className="py-3 text-center font-medium text-slate-650 dark:text-slate-350">{user.bookings} đơn</td>
                          <td className="py-3 text-right font-bold text-slate-800 dark:text-slate-200">{formatCurrency(user.revenue)}</td>
                          <td className="py-3 text-center">
                            <Badge className={cn(
                              "text-[9px] font-bold px-1.5 py-0.5",
                              user.status === 'Active' ? 'bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20 dark:text-emerald-400' :
                                user.status === 'Suspended' ? 'bg-amber-50 text-amber-700 dark:bg-amber-950/20 dark:text-amber-400' :
                                  'bg-red-50 text-red-500 dark:bg-red-950/20 dark:text-red-400'
                            )}>
                              {user.status === 'Active' ? 'Hoạt động' : user.status === 'Suspended' ? 'Tạm khóa' : 'Cấm'}
                            </Badge>
                          </td>
                          <td className="py-3 text-right">
                            <div className="flex gap-1 justify-end">
                              {user.status === 'Active' ? (
                                <>
                                  <button
                                    onClick={() => handleUpdateUserStatus(user.id, user.name, 'Suspended')}
                                    className="p-1 text-amber-600 hover:bg-amber-50 dark:hover:bg-slate-800 rounded transition-colors"
                                    title="Tạm Khóa"
                                  >
                                    <Lock className="h-3.5 w-3.5" />
                                  </button>
                                  <button
                                    onClick={() => handleUpdateUserStatus(user.id, user.name, 'Banned')}
                                    className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-slate-800 rounded transition-colors"
                                    title="Cấm tài khoản"
                                  >
                                    <ShieldAlert className="h-3.5 w-3.5" />
                                  </button>
                                </>
                              ) : (
                                <button
                                  onClick={() => handleUpdateUserStatus(user.id, user.name, 'Active')}
                                  className="p-1 text-emerald-500 hover:bg-emerald-50 dark:hover:bg-slate-800 rounded transition-colors"
                                  title="Kích hoạt lại"
                                >
                                  <Unlock className="h-3.5 w-3.5" />
                                </button>
                              )}
                              <button
                                onClick={() => handleResetPassword(user.name)}
                                className="p-1 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded transition-colors"
                                title="Reset mật khẩu"
                              >
                                <RefreshCw className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ====================================
            TAB: HOST MANAGEMENT
            ==================================== */}
        <TabsContent value="hosts" className="outline-hidden">
          <Card className="border border-slate-200/80 dark:border-slate-850">
            <CardHeader>
              <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Giám Sát Hiệu Suất Host</CardTitle>
              <CardDescription className="text-[11px] text-slate-400">Xem doanh thu, tỷ lệ lấp đầy, xếp hạng đánh giá và quản lý xác minh quyền Host.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                      <th className="pb-3 text-left font-bold">Chủ nhà (Host)</th>
                      <th className="pb-3 text-center font-bold">Khu đất sở hữu</th>
                      <th className="pb-3 text-right font-bold">Tổng doanh thu</th>
                      <th className="pb-3 text-center font-bold">Tỉ lệ lấp đầy TB</th>
                      <th className="pb-3 text-center font-bold">Đánh giá sao</th>
                      <th className="pb-3 text-center font-bold">Tỷ lệ hủy đơn</th>
                      <th className="pb-3 text-center font-bold">Superhost</th>
                      <th className="pb-3 text-right font-bold">Hành động quản trị</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {hostsList.map((host) => (
                      <tr key={host.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors">
                        <td className="py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-900 dark:text-slate-150">{host.name}</span>
                            {!host.verified && <Badge className="bg-amber-100 text-amber-800 text-[8px] font-bold">Chưa xác minh</Badge>}
                          </div>
                        </td>
                        <td className="py-3 text-center font-semibold text-slate-600 dark:text-slate-350">{host.properties} khu</td>
                        <td className="py-3 text-right font-extrabold text-slate-800 dark:text-slate-100">{formatCurrency(host.revenue)}</td>
                        <td className="py-3 text-center font-bold text-primary">{host.occupancy}%</td>
                        <td className="py-3 text-center font-bold text-amber-500 flex items-center justify-center gap-0.5 mt-2">
                          <Star className="h-3 w-3 fill-current" /> {host.rating}
                        </td>
                        <td className="py-3 text-center text-red-500 font-semibold">{host.cancellation}%</td>
                        <td className="py-3 text-center">
                          {host.superhost ? (
                            <Badge className="bg-amber-500 hover:bg-amber-600 text-white text-[9px] font-bold">Superhost</Badge>
                          ) : (
                            <span className="text-slate-400">Thường</span>
                          )}
                        </td>
                        <td className="py-3 text-right">
                          <div className="flex gap-1.5 justify-end">
                            {!host.verified ? (
                              <button
                                onClick={() => handleVerifyHost(host.id, host.name)}
                                className="px-2.5 py-1 text-[10px] font-bold bg-primary text-white rounded-md transition-colors"
                              >
                                Xác minh Host
                              </button>
                            ) : (
                              <button
                                onClick={() => handleSuspendHost(host.id, host.name)}
                                className="px-2.5 py-1 text-[10px] font-bold bg-amber-500 text-white rounded-md transition-colors"
                              >
                                Tạm dừng Host
                              </button>
                            )}
                            <button
                              onClick={() => toast.success(`Mở liên hệ với ${host.name}`)}
                              className="p-1 border hover:bg-slate-100 dark:hover:bg-slate-800 rounded transition-all"
                              title="Liên hệ"
                            >
                              <Mail className="h-3.5 w-3.5 text-slate-500" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ====================================
            TAB: LISTING MANAGEMENT
            ==================================== */}
        <TabsContent value="listings" className="outline-hidden">
          <Card className="border border-slate-200/80 dark:border-slate-850">
            <CardHeader>
              <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Kiểm Duyệt & Quản Lý Campsite Tin Đăng</CardTitle>

            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                      <th className="pb-3 text-left font-bold">Tên Campsite / Khu Đất</th>
                      <th className="pb-3 text-left font-bold font-bold">Chủ sở hữu (Host)</th>
                      <th className="pb-3 text-left font-bold">Vị trí</th>
                      <th className="pb-3 text-center font-bold">Loại hình</th>
                      <th className="pb-3 text-center font-bold">Điểm Rating</th>
                      <th className="pb-3 text-center font-bold">Trạng thái tin</th>
                      <th className="pb-3 text-right font-bold">Thao tác</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {listingsList.map((listing) => (
                      <tr key={listing.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors">
                        <td className="py-3 font-bold text-slate-900 dark:text-slate-150">{listing.name}</td>
                        <td className="py-3 font-semibold text-slate-600 dark:text-slate-350">{listing.host}</td>
                        <td className="py-3 font-medium text-slate-500">{listing.location}</td>
                        <td className="py-3 text-center">
                          <Badge className="bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 text-[9px] px-1.5 py-0.5">
                            {listing.type}
                          </Badge>
                        </td>
                        <td className="py-3 text-center font-bold text-amber-500">
                          {listing.rating > 0 ? (
                            <span className="flex items-center justify-center gap-0.5 mt-2">
                              <Star className="h-3 w-3 fill-current" /> {listing.rating}
                            </span>
                          ) : (
                            <span className="text-slate-400">Chưa xếp hạng</span>
                          )}
                        </td>
                        <td className="py-3 text-center">
                          <span className={cn(
                            "text-[10px] font-bold",
                            listing.status === 'Approved' ? 'text-emerald-500' :
                              listing.status === 'Pending Approval' ? 'text-amber-500' : 'text-red-500'
                          )}>
                            {listing.status === 'Approved' ? 'Đang hoạt động' : listing.status === 'Pending Approval' ? 'Chờ duyệt' : 'Bị tạm dừng'}
                          </span>
                        </td>
                        <td className="py-3 text-right">
                          <div className="flex gap-1.5 justify-end">
                            {listing.status === 'Pending Approval' ? (
                              <>
                                <button
                                  onClick={() => handleUpdateListingStatus(listing.id, listing.name, 'Approved')}
                                  className="px-2.5 py-1 text-[10px] font-bold bg-emerald-500 hover:bg-emerald-600 text-white rounded-md transition-colors"
                                >
                                  Duyệt
                                </button>
                                <button
                                  onClick={() => handleUpdateListingStatus(listing.id, listing.name, 'Rejected')}
                                  className="px-2.5 py-1 text-[10px] font-bold bg-red-500 hover:bg-red-600 text-white rounded-md transition-colors"
                                >
                                  Từ chối
                                </button>
                              </>
                            ) : listing.status === 'Approved' ? (
                              <button
                                onClick={() => handleUpdateListingStatus(listing.id, listing.name, 'Suspended')}
                                className="px-2.5 py-1 text-[10px] font-bold bg-amber-500 hover:bg-amber-600 text-white rounded-md transition-colors"
                              >
                                Tạm dừng
                              </button>
                            ) : (
                              <button
                                onClick={() => handleUpdateListingStatus(listing.id, listing.name, 'Approved')}
                                className="px-2.5 py-1 text-[10px] font-bold bg-emerald-500 hover:bg-emerald-600 text-white rounded-md transition-colors"
                              >
                                Phục hồi
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ====================================
            TAB: BOOKING MANAGEMENT
            ==================================== */}
        <TabsContent value="bookings" className="outline-hidden">
          <Card className="border border-slate-200/80 dark:border-slate-850">
            <CardHeader className="pb-3 flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-sm font-bold text-slate-800 dark:text-slate-200">Quản Lý Đơn Đặt Phòng (Bookings)</CardTitle>
                <CardDescription className="text-[11px] text-slate-400">Giám sát toàn bộ các đơn đặt lều cắm trại thời gian thực.</CardDescription>
              </div>
            </CardHeader>
            <CardContent>
              {/* Status summary */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-5">
                <div className="p-3 bg-slate-50/50 dark:bg-slate-900 border rounded-xl">
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider block">Tổng Booking</span>
                  <span className="text-md font-bold text-slate-850 dark:text-white block mt-1">{bookingsList.length} đơn</span>
                </div>
                <div className="p-3 bg-blue-50/50 dark:bg-blue-950/20 border border-blue-200/30 rounded-xl">
                  <span className="text-[9px] font-bold text-blue-500 uppercase tracking-wider block">Sắp diễn ra</span>
                  <span className="text-md font-bold text-blue-600 block mt-1">1 đơn</span>
                </div>
                <div className="p-3 bg-orange-50/50 dark:bg-orange-950/20 border border-orange-200/30 rounded-xl">
                  <span className="text-[9px] font-bold text-orange-500 uppercase tracking-wider block">Đang lưu trú</span>
                  <span className="text-md font-bold text-orange-600 block mt-1">1 đơn</span>
                </div>
                <div className="p-3 bg-emerald-50/50 dark:bg-emerald-950/20 border border-emerald-200/30 rounded-xl">
                  <span className="text-[9px] font-bold text-emerald-500 uppercase tracking-wider block">Hoàn thành</span>
                  <span className="text-md font-bold text-emerald-600 block mt-1">1 đơn</span>
                </div>
                <div className="p-3 bg-red-50/50 dark:bg-red-950/20 border border-red-200/30 rounded-xl">
                  <span className="text-[9px] font-bold text-red-500 uppercase tracking-wider block">Đã hủy</span>
                  <span className="text-md font-bold text-red-600 block mt-1">1 đơn</span>
                </div>
              </div>

              {/* Bookings Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                      <th className="pb-3 text-left font-bold">Mã Booking</th>
                      <th className="pb-3 text-left font-bold font-bold">Khách cắm trại</th>
                      <th className="pb-3 text-left font-bold">Host</th>
                      <th className="pb-3 text-left font-bold">Property / Campsite</th>
                      <th className="pb-3 text-right font-bold font-bold">Thành tiền</th>
                      <th className="pb-3 text-center font-bold">Trạng thái đơn</th>
                      <th className="pb-3 text-center font-bold">Thanh toán</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {bookingsList.map((booking) => (
                      <tr key={booking.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors">
                        <td className="py-3 font-semibold text-slate-500">{booking.id}</td>
                        <td className="py-3 font-bold text-slate-900 dark:text-slate-150">{booking.camper}</td>
                        <td className="py-3 font-semibold text-slate-600 dark:text-slate-355">{booking.host}</td>
                        <td className="py-3 font-medium text-slate-500 max-w-[160px] truncate">{booking.property}</td>
                        <td className="py-3 text-right font-extrabold text-primary">{formatCurrency(booking.amount)}</td>
                        <td className="py-3 text-center">
                          <span className={cn(
                            "text-[10px] font-bold",
                            booking.status === 'Confirmed' ? 'text-blue-500' :
                              booking.status === 'Pending' ? 'text-amber-500' :
                                booking.status === 'Completed' ? 'text-emerald-500' : 'text-red-500'
                          )}>
                            {getStatusText(booking.status)}
                          </span>
                        </td>
                        <td className="py-3 text-center">
                          <Badge className={cn(
                            "text-[9px] font-bold px-2 py-0.5",
                            booking.payment === 'Paid' ? 'bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20 dark:text-emerald-400' :
                              booking.payment === 'Pending' ? 'bg-amber-50 text-amber-700 dark:bg-amber-950/20 dark:text-amber-400' :
                                'bg-slate-100 text-slate-500'
                          )}>
                            {booking.payment === 'Paid' ? 'Đã thu' : booking.payment === 'Pending' ? 'Chưa trả' : 'Hoàn tiền'}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ====================================
            TAB: PAYMENTS & PAYOUTS
            ==================================== */}
        <TabsContent value="payments" className="outline-hidden">
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl border border-slate-200 bg-white dark:bg-slate-900 dark:border-slate-800/80 shadow-xs flex items-center gap-3">
                <div className="h-9 w-9 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 text-emerald-500 flex items-center justify-center shrink-0">
                  <DollarSign className="h-5 w-5" />
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Tổng Dòng Tiền</span>
                  <span className="text-md font-black text-slate-800 dark:text-slate-200">{formatCurrency(totalRevVal)}</span>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 bg-white dark:bg-slate-900 dark:border-slate-800/80 shadow-xs flex items-center gap-3">
                <div className="h-9 w-9 rounded-lg bg-amber-50 dark:bg-amber-950/20 text-amber-500 flex items-center justify-center shrink-0">
                  <Clock className="h-5 w-5" />
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Yêu Cầu Giải Ngân (Payout)</span>
                  <span className="text-md font-black text-amber-600">{payoutsList.filter(x => x.status === 'Pending').length} lệnh chờ</span>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 bg-white dark:bg-slate-900 dark:border-slate-800/80 shadow-xs flex items-center gap-3">
                <div className="h-9 w-9 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 flex items-center justify-center shrink-0">
                  <CheckSquare className="h-5 w-5" />
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Giải Ngân Hoàn Tất</span>
                  <span className="text-md font-bold text-slate-800 dark:text-slate-200">{formatCurrency(8900000)}</span>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 bg-white dark:bg-slate-900 dark:border-slate-800/80 shadow-xs flex items-center gap-3">
                <div className="h-9 w-9 rounded-lg bg-red-50 dark:bg-red-950/20 text-red-500 flex items-center justify-center shrink-0">
                  <RefreshCw className="h-5 w-5 animate-spin" />
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Yêu Cầu Hoàn Tiền</span>
                  <span className="text-md font-black text-red-500">{refundRequests.filter(x => x.status === 'Pending').length} yêu cầu</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Payout Queue */}
              <Card className="border border-slate-200/80 dark:border-slate-850">
                <CardHeader>
                  <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Hàng Đợi Giải Ngân Cho Host</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3.5">
                    {payoutsList.map((payout) => (
                      <div key={payout.id} className="p-3 bg-slate-50/50 dark:bg-slate-900/40 rounded-xl border flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <span className="text-[10px] font-semibold text-slate-400 uppercase block">{payout.id} • {payout.date}</span>
                          <span className="text-xs font-bold text-slate-800 dark:text-slate-250 block mt-0.5">Host: {payout.host}</span>
                          <span className="text-xs font-black text-primary block mt-0.5">{formatCurrency(payout.amount)}</span>
                        </div>
                        {payout.status === 'Pending' ? (
                          <button
                            onClick={() => handleReleasePayout(payout.id, payout.host, payout.amount)}
                            className="px-3 py-1.5 text-[10px] font-bold bg-primary text-white rounded-lg hover:bg-primary/90 transition-all shadow-sm"
                          >
                            Release Payout
                          </button>
                        ) : (
                          <Badge className="bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20 dark:text-emerald-450 border border-emerald-150">Đã thanh toán</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Refund Queue */}
              <Card className="border border-slate-200/80 dark:border-slate-850">
                <CardHeader>
                  <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Yêu Cầu Hoàn Tiền (Refunds)</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3.5">
                    {refundRequests.map((refund) => (
                      <div key={refund.id} className="p-3 bg-slate-50/50 dark:bg-slate-900/40 rounded-xl border flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <span className="text-[10px] font-semibold text-slate-400 uppercase block">{refund.id} • Booking: {refund.bookingId}</span>
                          <span className="text-xs font-bold text-slate-800 dark:text-slate-250 block mt-0.5">Camper: {refund.camper}</span>
                          <span className="text-[10px] text-red-500 block mt-0.5">Lý do: {refund.reason}</span>
                          <span className="text-xs font-black text-slate-900 dark:text-white block mt-0.5">{formatCurrency(refund.amount)}</span>
                        </div>
                        {refund.status === 'Pending' ? (
                          <button
                            onClick={() => handleProcessRefund(refund.id, refund.camper, refund.amount)}
                            className="px-3 py-1.5 text-[10px] font-bold bg-red-500 hover:bg-red-650 text-white rounded-lg transition-all"
                          >
                            Duyệt Hoàn Tiền
                          </button>
                        ) : (
                          <Badge className="bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20 dark:text-emerald-450 border border-emerald-150">Đã hoàn tiền</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Transactions Log */}
            <Card className="border border-slate-200/80 dark:border-slate-850">
              <CardHeader>
                <CardTitle className="text-sm font-bold text-slate-850 dark:text-white">Nhật Ký Giao Dịch Gần Đây</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                        <th className="pb-3 text-left font-bold">Mã giao dịch</th>
                        <th className="pb-3 text-center font-bold">Loại giao dịch</th>
                        <th className="pb-3 text-left font-bold">Thành viên liên quan</th>
                        <th className="pb-3 text-right font-bold">Giá trị</th>
                        <th className="pb-3 text-center font-bold">Thời gian</th>
                        <th className="pb-3 text-center font-bold">Trạng thái</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                      {transactions.map((tx) => (
                        <tr key={tx.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors">
                          <td className="py-3 font-semibold text-slate-500">{tx.id}</td>
                          <td className="py-3 text-center">
                            <Badge className={cn(
                              "text-[9px] font-bold px-1.5 py-0.5",
                              tx.type === 'Payment' ? 'bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20' :
                                tx.type === 'Payout' ? 'bg-indigo-50 text-indigo-600 dark:bg-indigo-950/20' :
                                  'bg-red-50 text-red-500 dark:bg-red-950/20'
                            )}>
                              {tx.type === 'Payment' ? 'Thu tiền' : tx.type === 'Payout' ? 'Chi trả' : 'Hoàn tiền'}
                            </Badge>
                          </td>
                          <td className="py-3 font-bold text-slate-800 dark:text-slate-250">{tx.user}</td>
                          <td className={cn(
                            "py-3 text-right font-extrabold",
                            tx.amount > 0 ? "text-emerald-500" : "text-red-500"
                          )}>
                            {tx.amount > 0 ? '+' : ''}{formatCurrency(tx.amount)}
                          </td>
                          <td className="py-3 text-center font-medium text-slate-500">{tx.date}</td>
                          <td className="py-3 text-center">
                            <span className={cn(
                              "text-[10px] font-semibold",
                              tx.status === 'Success' ? 'text-emerald-500' : 'text-amber-500'
                            )}>
                              {tx.status === 'Success' ? 'Thành công' : 'Đang xử lý'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}