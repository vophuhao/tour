/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    Calendar,
    Users,
    MapPin,
    Eye,
    MessageSquare,
    CheckCircle2,
    XCircle,
    Clock,
    Wallet,
    AlertTriangle,
    ChevronDown,
    Building,
} from "lucide-react";
import Image from "next/image";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { getMyBookings, guestConfirmArrival, guestCannotAttend } from "@/lib/client-actions";

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
    pending: { label: "Chờ xác nhận", color: "bg-yellow-100 text-yellow-800" },
    confirmed: { label: "Đã xác nhận", color: "bg-green-100 text-green-800" },
    cancelled: { label: "Đã hủy", color: "bg-red-100 text-red-800" },
    completed: { label: "Hoàn thành", color: "bg-blue-100 text-blue-800" },
    refunded: { label: "Đã hoàn tiền", color: "bg-purple-100 text-purple-800" },
    refund_requested: { label: "Yêu cầu hoàn tiền", color: "bg-orange-100 text-orange-800" },
};

const PAYMENT_STATUS_LABELS: Record<string, { label: string; color: string }> = {
    pending: { label: "Chờ thanh toán", color: "bg-yellow-100 text-yellow-800" },
    paid: { label: "Đã thanh toán", color: "bg-green-100 text-green-800" },
    refunded: { label: "Đã hoàn tiền", color: "bg-purple-100 text-purple-800" },
    failed: { label: "Thất bại", color: "bg-red-100 text-red-800" },
};

const STATUS_OPTIONS = [
    { value: 'all', label: 'Tất cả' },
    { value: 'pending', label: 'Chờ xác nhận' },
    { value: 'confirmed', label: 'Đã xác nhận' },
    { value: 'completed', label: 'Hoàn thành' },
    { value: 'cancelled', label: 'Đã hủy' },
];

/**
 * Kiểm tra xem nút "Xác nhận đã đến" có hiển thị không
 * Điều kiện: confirmed + paid + chưa confirm + trong khoảng [checkIn, checkOut + 3 ngày]
 */
function canConfirmArrival(booking: any): boolean {
    if (booking.status !== "confirmed") return false;
    if (booking.paymentStatus !== "paid") return false;
    if (booking.guestConfirmedAttendance) return false;
    if (booking.walletCredited) return false;
    if (booking.cannotAttendRequest) return false;

    const now = new Date();
    const checkIn = new Date(booking.checkIn);
    const checkOut = new Date(booking.checkOut);
    const deadline = new Date(checkOut.getTime() + 3 * 24 * 60 * 60 * 1000);

    return now >= checkIn && now <= deadline;
}

/**
 * Kiểm tra xem nút "Không thể đến" có hiển thị không
 * Điều kiện: 6h trước checkIn đến 6h sau checkIn
 */
function canReportCannotAttend(booking: any): boolean {
    if (booking.status !== "confirmed") return false;
    if (booking.paymentStatus !== "paid") return false;
    if (booking.guestConfirmedAttendance) return false;
    if (booking.cannotAttendRequest) return false;
    if (booking.walletCredited) return false;

    const now = new Date();
    const checkIn = new Date(booking.checkIn);
    const windowStart = new Date(checkIn.getTime() - 6 * 60 * 60 * 1000);
    const windowEnd = new Date(checkIn.getTime() + 6 * 60 * 60 * 1000);

    return now >= windowStart && now <= windowEnd;
}

function formatPrice(price: number) {
    return new Intl.NumberFormat("vi-VN").format(price);
}

function formatDate(date: string) {
    return new Date(date).toLocaleDateString("vi-VN", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
    });
}

function formatDateTime(date: string) {
    return new Date(date).toLocaleString("vi-VN", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
}

export default function BookingsPage() {
    const [bookings, setBookings] = useState<any[]>([]);
    const [filteredBookings, setFilteredBookings] = useState<any[]>([]);
    const [activeTab, setActiveTab] = useState("all");
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    // Cannot attend dialog state
    const [cannotAttendDialog, setCannotAttendDialog] = useState(false);
    const [selectedBooking, setSelectedBooking] = useState<any>(null);
    const [cannotAttendForm, setCannotAttendForm] = useState({
        reason: "",
        bankAccountName: "",
        bankAccountNumber: "",
        bankName: "",
    });
    const [submitting, setSubmitting] = useState(false);

    // Confirm arrival state
    const [confirmingArrival, setConfirmingArrival] = useState<string | null>(null);

    async function fetchBookings() {
        try {
            setLoading(true);
            const res = await getMyBookings();
            if (res.success) {
                setBookings(res.data ?? []);
            }
        } catch (error) {
            console.error("Error fetching bookings:", error);
            toast.error("Có lỗi khi tải danh sách booking");
        } finally {
            setTimeout(() => setLoading(false), 500);
        }
    }

    useEffect(() => {
        fetchBookings();
    }, []);

    useEffect(() => {
        let filtered = [...bookings];
        if (activeTab !== "all") {
            filtered = filtered.filter((b) => b.status === activeTab);
        }
        filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        setFilteredBookings(filtered);
    }, [bookings, activeTab]);

    async function handleConfirmArrival(booking: any) {
        const bId = booking.id || booking._id;
        setConfirmingArrival(bId);
        try {
            const res = await guestConfirmArrival(bId);
            if (res.success) {
                toast.success("✅ Xác nhận đã đến thành công! Host sẽ nhận được tiền vào ví.");
                await fetchBookings();
            } else {
                toast.error(res.message || "Có lỗi xảy ra");
            }
        } catch {
            toast.error("Có lỗi xảy ra khi xác nhận");
        } finally {
            setConfirmingArrival(null);
        }
    }

    async function handleCannotAttend() {
        if (!selectedBooking) return;
        if (!cannotAttendForm.reason.trim()) {
            toast.error("Vui lòng nhập lý do");
            return;
        }
        if (!cannotAttendForm.bankAccountNumber.trim() || !cannotAttendForm.bankAccountName.trim() || !cannotAttendForm.bankName.trim()) {
            toast.error("Vui lòng nhập đầy đủ thông tin ngân hàng để nhận hoàn tiền");
            return;
        }

        setSubmitting(true);
        try {
            const res = await guestCannotAttend(selectedBooking._id, {
                reason: cannotAttendForm.reason,
                bankAccountName: cannotAttendForm.bankAccountName,
                bankAccountNumber: cannotAttendForm.bankAccountNumber,
                bankName: cannotAttendForm.bankName,
            });
            if (res.success) {
                toast.success("Đã gửi yêu cầu thành công. Admin sẽ xét duyệt hoàn tiền trong thời gian sớm nhất.");
                setCannotAttendDialog(false);
                setCannotAttendForm({ reason: "", bankAccountName: "", bankAccountNumber: "", bankName: "" });
                await fetchBookings();
            } else {
                toast.error(res.message || "Có lỗi xảy ra");
            }
        } catch {
            toast.error("Có lỗi xảy ra");
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <div className="min-h-screen bg-gray-50 py-8">
            <div className="mx-auto max-w-4xl px-4 sm:px-6 space-y-6">

                {/* Header */}
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Chuyến đi của tôi</h1>
                    <p className="mt-1 text-sm text-gray-500">Quản lý tất cả các booking camping của bạn</p>
                </div>

                {/* Status tabs */}
                <div className="flex flex-wrap gap-2">
                    {STATUS_OPTIONS.map((status) => {
                        const count = status.value === 'all'
                            ? bookings.length
                            : bookings.filter(b => b.status === status.value).length;
                        return (
                            <button
                                key={status.value}
                                onClick={() => setActiveTab(status.value)}
                                className={`inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all ${activeTab === status.value
                                    ? 'bg-emerald-600 text-white shadow-md'
                                    : 'bg-white border border-gray-200 text-gray-600 hover:bg-gray-50'
                                    }`}
                            >
                                {status.label}
                                {count > 0 && (
                                    <span className={`inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-xs font-bold ${activeTab === status.value
                                        ? 'bg-white/20 text-white'
                                        : 'bg-emerald-100 text-emerald-700'
                                        }`}>
                                        {count}
                                    </span>
                                )}
                            </button>
                        );
                    })}
                </div>

                {/* Bookings List */}
                {loading ? (
                    <div className="flex items-center justify-center py-20">
                        <div className="h-8 w-8 animate-spin rounded-full border-4 border-emerald-500 border-t-transparent" />
                    </div>
                ) : filteredBookings.length === 0 ? (
                    <div className="py-16 text-center bg-white rounded-2xl border border-gray-100">
                        <Calendar className="mx-auto h-12 w-12 text-gray-300" />
                        <h3 className="mt-3 text-lg font-semibold text-gray-700">Chưa có booking nào</h3>
                        <p className="mt-1 text-sm text-gray-400">Hãy khám phá và đặt chỗ camping ngay hôm nay!</p>
                        <Button onClick={() => router.push('/search')} className="mt-4 bg-emerald-600 hover:bg-emerald-700">
                            Khám phá địa điểm
                        </Button>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {filteredBookings.map((booking) => {
                            const showConfirmArrival = canConfirmArrival(booking);
                            const showCannotAttend = canReportCannotAttend(booking);
                            const bId = booking.id || booking._id;
                            const isConfirming = confirmingArrival === bId;

                            return (
                                <div key={bId} className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden hover:shadow-md transition-shadow">
                                    <div className="flex flex-col sm:flex-row">
                                        {/* Image */}
                                        <div className="relative h-48 sm:h-auto sm:w-52 flex-shrink-0">
                                            <Image
                                                src={booking.campsite?.images?.[0] || booking.property?.photos?.[0] || "/placeholder.jpg"}
                                                alt={booking.campsite?.name || booking.property?.name || "Campsite"}
                                                fill
                                                className="object-cover"
                                            />
                                            <div className="absolute top-3 left-3 flex flex-col gap-1.5">
                                                <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold whitespace-nowrap ${STATUS_LABELS[booking.status]?.color || "bg-gray-100 text-gray-700"}`}>
                                                    {STATUS_LABELS[booking.status]?.label || booking.status}
                                                </span>
                                                <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold whitespace-nowrap ${PAYMENT_STATUS_LABELS[booking.paymentStatus]?.color || "bg-gray-100 text-gray-700"}`}>
                                                    {PAYMENT_STATUS_LABELS[booking.paymentStatus]?.label || booking.paymentStatus}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Content */}
                                        <div className="flex flex-1 flex-col p-5 gap-3">
                                            {/* Title + Price */}
                                            <div className="flex items-start justify-between gap-2">
                                                <div>
                                                    <h3 className="text-lg font-bold text-gray-900 leading-snug">
                                                        {booking.campsite?.name || booking.property?.name}
                                                    </h3>
                                                    <div className="flex items-center gap-1 mt-1 text-sm text-gray-500">
                                                        <MapPin className="h-3.5 w-3.5" />
                                                        <span>{booking.campsite?.location?.city || booking.property?.location?.city}</span>
                                                    </div>
                                                </div>
                                                <div className="text-right flex-shrink-0">
                                                    <p className="text-xl font-black text-emerald-600">{formatPrice(booking.pricing?.total)}₫</p>
                                                    <p className="text-xs text-gray-400">{booking.nights} đêm</p>
                                                </div>
                                            </div>

                                            {/* Dates */}
                                            <div className="grid grid-cols-3 gap-3 py-3 border-t border-b border-gray-100">
                                                <div>
                                                    <p className="text-xs text-gray-400">Check-in</p>
                                                    <p className="mt-0.5 text-sm font-semibold">{formatDate(booking.checkIn)}</p>
                                                </div>
                                                <div>
                                                    <p className="text-xs text-gray-400">Check-out</p>
                                                    <p className="mt-0.5 text-sm font-semibold">{formatDate(booking.checkOut)}</p>
                                                </div>
                                                <div>
                                                    <p className="text-xs text-gray-400">Khách</p>
                                                    <p className="mt-0.5 text-sm font-semibold flex items-center gap-1">
                                                        <Users className="h-3.5 w-3.5 text-gray-400" />
                                                        {booking.numberOfGuests} người
                                                    </p>
                                                </div>
                                            </div>

                                            {/* Status banners */}
                                            {booking.guestConfirmedAttendance && (
                                                <div className="flex items-center gap-2 px-3 py-2 bg-emerald-50 rounded-lg border border-emerald-200">
                                                    <CheckCircle2 className="h-4 w-4 text-emerald-600 flex-shrink-0" />
                                                    <span className="text-sm text-emerald-700 font-medium">
                                                        Bạn đã xác nhận đến lúc {booking.guestConfirmedAt ? formatDateTime(booking.guestConfirmedAt) : ""}
                                                    </span>
                                                </div>
                                            )}

                                            {booking.cannotAttendRequest && (
                                                <div className={`flex items-start gap-2 px-3 py-2 rounded-lg border ${booking.cannotAttendRequest.status === "approved"
                                                    ? "bg-green-50 border-green-200"
                                                    : booking.cannotAttendRequest.status === "rejected"
                                                        ? "bg-red-50 border-red-200"
                                                        : "bg-amber-50 border-amber-200"
                                                    }`}>
                                                    <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" />
                                                    <div>
                                                        <p className="text-sm font-medium text-amber-800">Đã báo không thể đến</p>
                                                        <p className="text-xs text-amber-600 mt-0.5">
                                                            Hoàn tiền {formatPrice(booking.cannotAttendRequest.refundAmount || 0)}₫ ({booking.cannotAttendRequest.refundRate !== undefined ? `${Math.round(booking.cannotAttendRequest.refundRate * 100)}%` : "50%"}) —
                                                            {booking.cannotAttendRequest.status === "pending" && " Đang chờ admin xét duyệt"}
                                                            {booking.cannotAttendRequest.status === "approved" && " Đã được duyệt"}
                                                            {booking.cannotAttendRequest.status === "rejected" && " Đã bị từ chối"}
                                                        </p>
                                                        {booking.cannotAttendRequest.adminNote && (
                                                            <p className="text-xs text-gray-600 mt-1">Ghi chú: {booking.cannotAttendRequest.adminNote}</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Check-in window hint */}
                                            {booking.status === "confirmed" && booking.paymentStatus === "paid" &&
                                                !booking.guestConfirmedAttendance && !booking.cannotAttendRequest && !booking.walletCredited && (
                                                    <div className="flex items-center gap-2 px-3 py-2 bg-blue-50 rounded-lg border border-blue-200">
                                                        <Clock className="h-4 w-4 text-blue-500 flex-shrink-0" />
                                                        <span className="text-xs text-blue-700">
                                                            Nút xác nhận đến sẽ hiện từ ngày check-in đến 3 ngày sau check-out.
                                                            Nút báo không đến hiện trong 6 giờ trước/sau check-in.
                                                        </span>
                                                    </div>
                                                )}

                                            {/* Actions */}
                                            <div className="flex flex-wrap gap-2 pt-1">
                                                <Button
                                                    onClick={() => router.push(`/bookings/${booking.id || booking._id}/confirmation`)}
                                                    variant="outline"
                                                    size="sm"
                                                    className="flex items-center gap-1.5"
                                                >
                                                    <Eye className="h-4 w-4" />
                                                    Xem chi tiết
                                                </Button>

                                                {showConfirmArrival && (
                                                    <Button
                                                        onClick={() => handleConfirmArrival(booking)}
                                                        disabled={isConfirming}
                                                        size="sm"
                                                        className="bg-emerald-600 hover:bg-emerald-700 text-white flex items-center gap-1.5"
                                                    >
                                                        {isConfirming ? (
                                                            <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                                                        ) : (
                                                            <CheckCircle2 className="h-4 w-4" />
                                                        )}
                                                        Xác nhận đã đến
                                                    </Button>
                                                )}

                                                {showCannotAttend && (
                                                    <Button
                                                        onClick={() => {
                                                            setSelectedBooking(booking);
                                                            setCannotAttendDialog(true);
                                                        }}
                                                        size="sm"
                                                        variant="outline"
                                                        className="border-red-300 text-red-600 hover:bg-red-50 flex items-center gap-1.5"
                                                    >
                                                        <XCircle className="h-4 w-4" />
                                                        Không thể đến
                                                    </Button>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* Cannot Attend Dialog */}
            <Dialog open={cannotAttendDialog} onOpenChange={setCannotAttendDialog}>
                <DialogContent className="max-w-md">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2 text-red-600">
                            <XCircle className="h-5 w-5" />
                            Báo không thể đến
                        </DialogTitle>
                        <DialogDescription>
                            Khi xác nhận không đến, host sẽ nhận <strong>30%</strong> số tiền. Admin sẽ xét duyệt hoàn lại cho bạn <strong>50%</strong> ({selectedBooking ? formatPrice(Math.round(selectedBooking.pricing?.total * 0.5)) : 0}₫) nếu có lý do hợp lệ.
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4 py-2">
                        <div>
                            <Label htmlFor="cannot-reason" className="text-sm font-medium">Lý do không thể đến *</Label>
                            <Textarea
                                id="cannot-reason"
                                placeholder="Nhập lý do cụ thể..."
                                value={cannotAttendForm.reason}
                                onChange={(e) => setCannotAttendForm(f => ({ ...f, reason: e.target.value }))}
                                className="mt-1.5"
                                rows={3}
                            />
                        </div>

                        <div className="rounded-lg bg-gray-50 p-3 space-y-3">
                            <p className="text-sm font-semibold text-gray-700 flex items-center gap-1.5">
                                <Building className="h-4 w-4" />
                                Thông tin ngân hàng nhận hoàn tiền *
                            </p>
                            <div>
                                <Label htmlFor="bank-name" className="text-xs text-gray-600">Tên ngân hàng</Label>
                                <Input
                                    id="bank-name"
                                    placeholder="VD: Vietcombank, Techcombank..."
                                    value={cannotAttendForm.bankName}
                                    onChange={(e) => setCannotAttendForm(f => ({ ...f, bankName: e.target.value }))}
                                    className="mt-1 h-9 text-sm"
                                />
                            </div>
                            <div>
                                <Label htmlFor="bank-account-name" className="text-xs text-gray-600">Tên chủ tài khoản</Label>
                                <Input
                                    id="bank-account-name"
                                    placeholder="Tên đầy đủ theo ngân hàng"
                                    value={cannotAttendForm.bankAccountName}
                                    onChange={(e) => setCannotAttendForm(f => ({ ...f, bankAccountName: e.target.value }))}
                                    className="mt-1 h-9 text-sm"
                                />
                            </div>
                            <div>
                                <Label htmlFor="bank-account-number" className="text-xs text-gray-600">Số tài khoản</Label>
                                <Input
                                    id="bank-account-number"
                                    placeholder="Nhập số tài khoản"
                                    value={cannotAttendForm.bankAccountNumber}
                                    onChange={(e) => setCannotAttendForm(f => ({ ...f, bankAccountNumber: e.target.value }))}
                                    className="mt-1 h-9 text-sm"
                                />
                            </div>
                        </div>

                        <p className="text-xs text-gray-500 bg-amber-50 border border-amber-200 rounded-lg p-3">
                            ⚠️ Lưu ý: Chỉ hoàn <strong>50%</strong> số tiền đã thanh toán. Admin sẽ xem xét và quyết định trong vòng 1-3 ngày làm việc.
                        </p>
                    </div>

                    <DialogFooter>
                        <Button variant="outline" onClick={() => setCannotAttendDialog(false)} disabled={submitting}>
                            Hủy
                        </Button>
                        <Button
                            onClick={handleCannotAttend}
                            disabled={submitting}
                            className="bg-red-600 hover:bg-red-700 text-white"
                        >
                            {submitting ? "Đang gửi..." : "Xác nhận không đến"}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}