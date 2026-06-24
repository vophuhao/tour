/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ArrowDownToLine,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  Search,
  Building,
  User,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  Wallet,
} from "lucide-react";
import { adminGetAllWithdrawals, adminProcessWithdrawal } from "@/lib/client-actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

function fmt(n: number) {
  return new Intl.NumberFormat("vi-VN").format(n || 0);
}
function fmtDate(d: string) {
  return new Date(d).toLocaleString("vi-VN", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

const STATUS = {
  pending: { label: "Chờ duyệt", color: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300", icon: Clock },
  processing: { label: "Đang xử lý", color: "bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary", icon: RefreshCw },
  completed: { label: "Hoàn tất", color: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300", icon: CheckCircle2 },
  rejected: { label: "Bị từ chối", color: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300", icon: XCircle },
};

export default function AdminWithdrawalsPage() {
  const [withdrawals, setWithdrawals] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("pending");
  const [search, setSearch] = useState("");
  const [stats, setStats] = useState({ pendingCount: 0, pendingAmount: 0 });

  // Process dialog
  const [processDialog, setProcessDialog] = useState<{
    open: boolean; withdrawal: any; approved: boolean;
  }>({ open: false, withdrawal: null, approved: true });
  const [adminNote, setAdminNote] = useState("");
  const [processing, setProcessing] = useState(false);

  async function fetchWithdrawals() {
    setLoading(true);
    try {
      const params: any = {};
      if (statusFilter !== "all") params.status = statusFilter;
      const res = await adminGetAllWithdrawals(params);
      if (res.success) {
        const data = res.data as any;
        setWithdrawals(data?.withdrawals || []);
        setStats({
          pendingCount: data?.pendingCount || 0,
          pendingAmount: data?.pendingAmount || 0,
        });
      }
    } catch {
      toast.error("Không thể tải dữ liệu");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchWithdrawals();
  }, [statusFilter]);

  async function handleProcess() {
    if (!processDialog.withdrawal) return;
    setProcessing(true);
    try {
      const res = await adminProcessWithdrawal(
        processDialog.withdrawal._id,
        processDialog.approved,
        adminNote
      );
      if (res.success) {
        toast.success(processDialog.approved ? "Đã duyệt lệnh rút!" : "Đã từ chối lệnh rút");
        setProcessDialog({ open: false, withdrawal: null, approved: true });
        setAdminNote("");
        await fetchWithdrawals();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    } catch {
      toast.error("Có lỗi xảy ra");
    } finally {
      setProcessing(false);
    }
  }

  const filtered = withdrawals.filter((w) => {
    if (!search) return true;
    const term = search.toLowerCase();
    return (
      w.host?.username?.toLowerCase().includes(term) ||
      w.host?.email?.toLowerCase().includes(term) ||
      w.bankInfo?.accountNumber?.includes(term)
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
          <Wallet className="h-6 w-6 text-primary" />
          Quản lý Rút tiền Host
        </h1>
        <p className="text-sm text-slate-500 mt-1">Duyệt các lệnh rút tiền từ ví host</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-2xl p-5">
          <p className="text-amber-600 text-sm font-medium">Đang chờ duyệt</p>
          <p className="text-3xl font-black text-amber-700 dark:text-amber-300 mt-1">{stats.pendingCount} lệnh</p>
        </div>
        <div className="bg-primary/10 dark:bg-primary/20 border border-primary/20 rounded-2xl p-5">
          <p className="text-primary text-sm font-medium">Tổng tiền chờ rút</p>
          <p className="text-3xl font-black text-primary mt-1">{fmt(stats.pendingAmount)}₫</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <Input
            placeholder="Tìm host, số TK..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Trạng thái" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tất cả</SelectItem>
            <SelectItem value="pending">Chờ duyệt</SelectItem>
            <SelectItem value="processing">Đang xử lý</SelectItem>
            <SelectItem value="completed">Hoàn tất</SelectItem>
            <SelectItem value="rejected">Từ chối</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
          <ArrowDownToLine className="h-10 w-10 text-slate-300 mx-auto" />
          <p className="text-slate-500 mt-3">Không có lệnh rút nào</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((wd) => {
            const st = STATUS[wd.status as keyof typeof STATUS] || STATUS.pending;
            const Icon = st.icon;
            const isPending = wd.status === "pending" || wd.status === "processing";

            return (
              <div
                key={wd._id}
                className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden"
              >
                <div className="p-5">
                  <div className="flex items-start justify-between gap-4">
                    {/* Host info */}
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-full bg-primary/10 dark:bg-primary/20 flex items-center justify-center text-primary font-bold text-sm flex-shrink-0">
                        {wd.host?.username?.[0]?.toUpperCase() || "H"}
                      </div>
                      <div>
                        <p className="font-semibold text-slate-800 dark:text-slate-200">
                          {wd.host?.username || "Host"}
                        </p>
                        <p className="text-xs text-slate-400">{wd.host?.email}</p>
                        <p className="text-xs text-slate-400">{fmtDate(wd.createdAt)}</p>
                      </div>
                    </div>

                    {/* Amount + status */}
                    <div className="text-right flex-shrink-0">
                      <p className="text-2xl font-black text-primary">
                        {fmt(wd.amount)}₫
                      </p>
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold mt-1 ${st.color}`}>
                        <Icon className="h-3.5 w-3.5" />
                        {st.label}
                      </span>
                    </div>
                  </div>

                  {/* Bank info */}
                  <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl p-3">
                    <div>
                      <p className="text-[10px] text-slate-400 uppercase tracking-wide">Ngân hàng</p>
                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mt-0.5">{wd.bankInfo?.bankName}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-slate-400 uppercase tracking-wide">Số tài khoản</p>
                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mt-0.5 font-mono">{wd.bankInfo?.accountNumber}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-slate-400 uppercase tracking-wide">Chủ tài khoản</p>
                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mt-0.5">{wd.bankInfo?.accountHolderName}</p>
                    </div>
                  </div>

                  {wd.adminNote && (
                    <p className="text-xs text-slate-500 mt-3 italic bg-slate-50 dark:bg-slate-800/40 p-2 rounded-lg">
                      Ghi chú admin: "{wd.adminNote}"
                    </p>
                  )}

                  {/* Actions */}
                  {isPending && (
                    <div className="flex gap-2 mt-4">
                      <Button
                        size="sm"
                        className="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white gap-1.5"
                        onClick={() => {
                          setProcessDialog({ open: true, withdrawal: wd, approved: true });
                          setAdminNote("");
                        }}
                      >
                        <CheckCircle2 className="h-4 w-4" />
                        Duyệt & Chuyển tiền
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1 border-red-300 text-red-600 hover:bg-red-50 gap-1.5"
                        onClick={() => {
                          setProcessDialog({ open: true, withdrawal: wd, approved: false });
                          setAdminNote("");
                        }}
                      >
                        <XCircle className="h-4 w-4" />
                        Từ chối
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Process Dialog */}
      <Dialog open={processDialog.open} onOpenChange={(o) => !o && setProcessDialog({ ...processDialog, open: false })}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className={`flex items-center gap-2 ${processDialog.approved ? "text-emerald-700" : "text-red-700"}`}>
              {processDialog.approved ? (
                <><CheckCircle2 className="h-5 w-5" /> Duyệt lệnh rút tiền</>
              ) : (
                <><XCircle className="h-5 w-5" /> Từ chối lệnh rút tiền</>
              )}
            </DialogTitle>
            <DialogDescription>
              {processDialog.withdrawal && (
                <>
                  Host: <strong>{processDialog.withdrawal.host?.username}</strong> — Số tiền:{" "}
                  <strong className="text-primary">{fmt(processDialog.withdrawal.amount)}₫</strong>
                  <br />
                  {processDialog.approved ? (
                    <span className="text-emerald-600">
                      Chuyển khoản tới: {processDialog.withdrawal.bankInfo?.accountNumber} ({processDialog.withdrawal.bankInfo?.bankName})
                    </span>
                  ) : (
                    <span className="text-red-600">Tiền sẽ được hoàn lại vào ví host.</span>
                  )}
                </>
              )}
            </DialogDescription>
          </DialogHeader>

          <div className="py-2 space-y-3">
            <div>
              <Label htmlFor="admin-note">Ghi chú (tuỳ chọn)</Label>
              <Textarea
                id="admin-note"
                placeholder={processDialog.approved ? "VD: Đã chuyển khoản lúc 10:00 ngày 25/05" : "VD: Thông tin ngân hàng không hợp lệ"}
                value={adminNote}
                onChange={(e) => setAdminNote(e.target.value)}
                className="mt-1.5"
                rows={3}
              />
            </div>

            {processDialog.approved && (
              <div className="bg-primary/10 border border-primary/20 rounded-lg p-3">
                <p className="text-xs text-primary flex items-start gap-1.5">
                  <AlertCircle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
                  Sau khi xác nhận, số tiền sẽ bị trừ khỏi ví host. Hãy chắc chắn đã thực hiện chuyển khoản thực tế.
                </p>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setProcessDialog({ ...processDialog, open: false })}
              disabled={processing}
            >
              Hủy
            </Button>
            <Button
              onClick={handleProcess}
              disabled={processing}
              className={processDialog.approved
                ? "bg-emerald-600 hover:bg-emerald-700 text-white"
                : "bg-red-600 hover:bg-red-700 text-white"
              }
            >
              {processing ? "Đang xử lý..." : processDialog.approved ? "Xác nhận đã chuyển tiền" : "Xác nhận từ chối"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
