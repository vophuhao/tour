/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @next/next/no-img-element */
'use client';

import { useEffect, useState } from 'react';
import { 
  Search, 
  Filter, 
  Ban, 
  CheckCircle, 
  Users, 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Unlock, 
  RefreshCw, 
  AlertTriangle,
  UserCheck,
  UserMinus,
  Calendar,
  Phone,
  Mail,
  UserX,
} from 'lucide-react';
import { toast } from 'sonner';
import { blockedUser, getAllUsers } from '@/lib/client-actions';
import { cn } from '@/lib/utils';

export default function UsersManagementPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [verifiedFilter, setVerifiedFilter] = useState<string>('all');
  const [showFilters, setShowFilters] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showBlockModal, setShowBlockModal] = useState(false);

  useEffect(() => {
    loadUsers();
  }, []);

  useEffect(() => {
    filterUsers();
  }, [users, searchQuery, roleFilter, verifiedFilter]);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const result = await getAllUsers();
      if (result.success) {
        setUsers((result.data as User[]) || []);
      }
    } catch (err) {
      console.error('Load users error:', err);
      toast.error('Không thể tải danh sách người dùng');
    } finally {
      setLoading(false);
    }
  };

  const filterUsers = () => {
    let filtered = [...users];

    // Search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (u) =>
          u.username.toLowerCase().includes(query) ||
          u.email.toLowerCase().includes(query) ||
          (u as any).phone?.toLowerCase().includes(query) ||
          (u as any).phoneNumber?.toLowerCase().includes(query)
      );
    }

    // Role filter
    if (roleFilter !== 'all') {
      filtered = filtered.filter((u) => u.role === roleFilter);
    }

    // Verified filter
    if (verifiedFilter !== 'all') {
      filtered = filtered.filter((u) =>
        verifiedFilter === 'verified' ? u.isVerified : !u.isVerified
      );
    }

    setFilteredUsers(filtered);
  };

  const handleBlockUser = async () => {
    if (!selectedUser) return;
    const isBlocked = selectedUser.isBlocked;
    try {
      const response = await blockedUser(selectedUser._id); 
      if (response.success) {
        toast.success(isBlocked ? 'Mở khóa người dùng thành công' : 'Khóa người dùng thành công');
        loadUsers();
      } else {
        toast.error(response.message);
      }
    } catch (err) {
      console.error('Block user error:', err);
      toast.error(isBlocked ? 'Không thể mở khóa người dùng' : 'Không thể khóa người dùng');
    }
    setShowBlockModal(false);
    setSelectedUser(null);
  };

  // Derive stats dynamically from total loaded users
  const totalCount = users.length;
  const adminCount = users.filter(u => u.role?.toLowerCase() === 'admin').length;
  const hostCount = users.filter(u => u.role?.toLowerCase() === 'host').length;
  const blockedCount = users.filter(u => u.isBlocked).length;

  const statCards = [
    {
      label: 'Tổng người dùng',
      value: totalCount,
      icon: Users,
      bg: 'bg-primary/10 dark:bg-primary/20',
      color: 'text-primary dark:text-primary',
    },
    {
      label: 'Quản trị viên',
      value: adminCount,
      icon: ShieldAlert,
      bg: 'bg-fuchsia-50 dark:bg-fuchsia-950/30',
      color: 'text-fuchsia-600 dark:text-fuchsia-400',
    },
    {
      label: 'Chủ nhà (Host)',
      value: hostCount,
      icon: UserCheck,
      bg: 'bg-primary/10 dark:bg-primary/20',
      color: 'text-primary dark:text-primary',
    },
    {
      label: 'Tài khoản bị khóa',
      value: blockedCount,
      icon: UserMinus,
      bg: 'bg-rose-50 dark:bg-rose-950/30',
      color: 'text-rose-600 dark:text-rose-400',
    },
  ];

  const getRoleBadge = (role: string) => {
    switch (role.toLowerCase()) {
      case 'admin':
        return 'bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 border border-fuchsia-500/20';
      case 'host':
        return 'bg-primary/10 text-primary dark:text-primary border border-primary/20';
      default:
        return 'bg-primary/10 text-primary dark:text-primary border border-primary/20';
    }
  };

  const getRoleText = (role: string) => {
    switch (role.toLowerCase()) {
      case 'admin':
        return 'Quản trị viên';
      case 'host':
        return 'Chủ nhà';
      default:
        return 'Người dùng';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">Quản lý người dùng</h1>
          <p className="text-xs text-slate-400 font-semibold mt-0.5">
            Xem, phân quyền và khóa/mở khóa tài khoản thành viên hệ thống.
          </p>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((s) => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4.5 flex items-center gap-4 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md shadow-xs">
              <div className={cn("w-11 h-11 rounded-xl flex items-center justify-center shadow-inner", s.bg)}>
                <Icon className={cn("h-5.5 w-5.5", s.color)} />
              </div>
              <div>
                <div className="text-xs text-slate-400 font-semibold">{s.label}</div>
                <div className={cn("text-lg font-black mt-0.5", s.color)}>{s.value}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Actions and Filters Bar */}
      <div className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3 flex-1">
            {/* Search Input */}
            <div className="relative w-full max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Tìm theo tên, email, điện thoại..."
                className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-700 dark:text-slate-205 focus:ring-2 focus:ring-primary/20 focus:outline-none"
              />
            </div>

            {/* Filter Toggle Button */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer",
                showFilters
                  ? "border-primary bg-primary/10 text-primary dark:text-primary"
                  : "border-slate-255 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-655 dark:text-slate-350 hover:bg-slate-50 dark:hover:bg-slate-900"
              )}
            >
              <Filter className="h-3.5 w-3.5" /> Bộ lọc
            </button>

            {/* Refresh Button */}
            <button
              onClick={loadUsers}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 text-xs font-bold text-slate-650 dark:text-slate-350 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Làm mới
            </button>
          </div>

          <div className="text-xs text-slate-400 font-semibold">
            Kết quả: <strong className="text-slate-700 dark:text-slate-200 font-extrabold">{filteredUsers.length}</strong> / {totalCount}
          </div>
        </div>

        {/* Expandable filters */}
        {showFilters && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-slate-100 dark:border-slate-800/60">
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Vai trò</label>
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-705 dark:text-slate-200"
              >
                <option value="all">Tất cả vai trò</option>
                <option value="user">Người dùng (Member)</option>
                <option value="host">Chủ nhà (Host)</option>
                <option value="admin">Quản trị viên (Admin)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Xác thực email</label>
              <select
                value={verifiedFilter}
                onChange={(e) => setVerifiedFilter(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-705 dark:text-slate-200"
              >
                <option value="all">Tất cả trạng thái</option>
                <option value="verified">Đã xác thực</option>
                <option value="unverified">Chưa xác thực</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Users Table */}
      {loading ? (
        <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-855 rounded-2xl">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
        </div>
      ) : filteredUsers.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-855 rounded-2xl shadow-xs text-slate-400">
          <UserX className="h-12 w-12 text-slate-200 dark:text-slate-800 mb-3" />
          <p className="text-sm font-semibold">Không tìm thấy người dùng nào phù hợp</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-855 rounded-2xl shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-805 bg-slate-50/50 dark:bg-slate-950 text-slate-400 font-bold text-xs uppercase tracking-wider">
                  <th className="px-5 py-3.5 font-bold">Người dùng</th>
                  <th className="px-5 py-3.5 font-bold">Email</th>
                  <th className="px-5 py-3.5 font-bold">Vai trò</th>
                  <th className="px-5 py-3.5 font-bold">Xác thực</th>
                  <th className="px-5 py-3.5 font-bold">Tài khoản</th>
                  <th className="px-5 py-3.5 font-bold">Ngày tham gia</th>
                  <th className="px-5 py-3.5 font-bold text-right">Khóa / Mở khóa</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {filteredUsers.map((user) => (
                  <tr key={user._id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors">
                    {/* User profile with avatar & username */}
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-3">
                        {user.avatarUrl ? (
                          <img
                            src={user.avatarUrl}
                            alt={user.username}
                            className="h-9 w-9 rounded-full object-cover ring-2 ring-slate-100 dark:ring-slate-800"
                          />
                        ) : (
                          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 dark:bg-primary/20 text-xs font-bold text-primary ring-2 ring-primary/20">
                            {user.username.slice(0, 2).toUpperCase()}
                          </div>
                        )}
                        <div>
                          <div className="font-bold text-slate-900 dark:text-slate-100">{user.username}</div>
                          {((user as any).phone || (user as any).phoneNumber) && (
                            <div className="text-[10px] text-slate-400 flex items-center gap-1 mt-0.5">
                              <Phone className="h-2.5 w-2.5" /> {(user as any).phone || (user as any).phoneNumber}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* Email */}
                    <td className="px-5 py-3.5 text-xs font-semibold text-slate-600 dark:text-slate-350">
                      <div className="flex items-center gap-1.5">
                        <Mail className="h-3.5 w-3.5 text-slate-400" />
                        {user.email}
                      </div>
                    </td>

                    {/* Role */}
                    <td className="px-5 py-3.5">
                      <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-extrabold border uppercase tracking-wider', getRoleBadge(user.role))}>
                        {getRoleText(user.role)}
                      </span>
                    </td>

                    {/* Verified Status */}
                    <td className="px-5 py-3.5">
                      {user.isVerified ? (
                        <span className="inline-flex items-center gap-1 text-xs text-primary dark:text-primary font-bold">
                          <CheckCircle className="h-3.5 w-3.5" />
                          Đã xác thực
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-slate-400 dark:text-slate-500 font-medium">
                          <Ban className="h-3.5 w-3.5" />
                          Chưa xác thực
                        </span>
                      )}
                    </td>

                    {/* Account Block Status */}
                    <td className="px-5 py-3.5">
                      {user.isBlocked ? (
                        <span className="inline-flex items-center gap-1 text-xs text-rose-600 dark:text-rose-450 font-bold bg-rose-50 dark:bg-rose-950/20 px-2 py-0.5 rounded-full border border-rose-500/10">
                          <ShieldAlert className="h-3.5 w-3.5" />
                          Đã khóa
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-primary dark:text-primary font-bold bg-primary/10 dark:bg-primary/20 px-2 py-0.5 rounded-full border border-primary/10">
                          <ShieldCheck className="h-3.5 w-3.5" />
                          Hoạt động
                        </span>
                      )}
                    </td>

                    {/* Created Date */}
                    <td className="px-5 py-3.5 text-xs text-slate-400 font-semibold">
                      <div className="flex items-center gap-1.5">
                        <Calendar className="h-3.5 w-3.5 text-slate-400" />
                        {new Date(user.createdAt).toLocaleDateString('vi-VN')}
                      </div>
                    </td>

                    {/* Action toggles (Block / Unblock) */}
                    <td className="px-5 py-3.5 text-right">
                      <button
                        onClick={() => {
                          setSelectedUser(user);
                          setShowBlockModal(true);
                        }}
                        className={cn(
                          "inline-flex items-center justify-center p-1.5 rounded-lg border transition-all cursor-pointer shadow-sm hover:shadow",
                          user.isBlocked
                            ? "text-primary border-primary/20 bg-primary/10 hover:bg-primary/20 hover:text-primary dark:text-primary dark:border-primary/20 dark:bg-primary/20 dark:hover:bg-primary/30"
                            : "text-rose-600 border-rose-200 bg-rose-50 hover:bg-rose-100 hover:text-rose-700 dark:text-rose-400 dark:border-rose-900/50 dark:bg-rose-950/20 dark:hover:bg-rose-950/40"
                        )}
                        title={user.isBlocked ? 'Mở khóa tài khoản' : 'Khóa tài khoản'}
                      >
                        {user.isBlocked ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      {showBlockModal && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 animate-fade-in">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center shadow-inner", selectedUser.isBlocked ? "bg-primary/10 dark:bg-primary/20 text-primary" : "bg-rose-50 dark:bg-rose-950 text-rose-650 dark:text-rose-455")}>
                <AlertTriangle className="h-5 w-5" />
              </div>
              <h3 className="text-md font-black text-slate-850 dark:text-slate-100">
                {selectedUser.isBlocked ? 'Mở khóa tài khoản?' : 'Khóa tài khoản?'}
              </h3>
            </div>
            
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Bạn có chắc chắn muốn {selectedUser.isBlocked ? 'mở khóa' : 'khóa'} tài khoản của người dùng{' '}
              <strong className="text-slate-700 dark:text-slate-200 font-extrabold">{selectedUser.username}</strong> ({selectedUser.email})? 
              {!selectedUser.isBlocked && " Người dùng sẽ không thể đăng nhập vào hệ thống khi bị khóa."}
            </p>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => {
                  setShowBlockModal(false);
                  setSelectedUser(null);
                }}
                className="rounded-xl border border-slate-255 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 py-2 text-xs font-bold text-slate-655 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
              >
                Hủy bỏ
              </button>
              <button
                onClick={handleBlockUser}
                className={cn(
                  "rounded-xl px-4 py-2 text-xs font-bold text-white transition-colors cursor-pointer shadow-xs",
                  selectedUser.isBlocked
                    ? "bg-primary hover:bg-primary/90"
                    : "bg-rose-600 hover:bg-rose-700 dark:bg-rose-500 dark:hover:bg-rose-600"
                )}
              >
                {selectedUser.isBlocked ? 'Mở khóa' : 'Xác nhận khóa'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}