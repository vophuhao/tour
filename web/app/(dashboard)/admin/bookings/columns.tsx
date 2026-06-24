/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { DataTable } from '@/components/data-table';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { useQuery } from '@tanstack/react-query';
import Image from 'next/image';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { columns as baseColumns } from './columns';

// Adapted columns for Tour Booking
import { ColumnDef } from '@tanstack/react-table';
import { getAllBookings } from '@/lib/api';

export type TourBooking = {
  _id: string;
  code: string;
  tour: { name: string } | string;
  dateFrom: string;
  dateTo: string;
  availableSeats: number;
  note?: string;
  customers: Array<{
    fullname: string;
    phone: string;
    email?: string;
    adults: number;
    children: number;
    babies: number;
    numberOfPeople: number;
    paymentStatus: 'pending' | 'paid' | 'failed';
    notes?: string;
  }>;
  status: 'pending' | 'completed' | 'cancelled';
  createdAt: string;
  updatedAt: string;
};

// Columns for tour booking table
export const columns: ColumnDef<TourBooking>[] = [
  {
    accessorKey: 'code',
    header: 'Mã Booking',
    cell: ({ row }) => row.getValue('code'),
  },
  {
    accessorKey: 'tour',
    header: 'Tour',
    cell: ({ row }) => {
    const t = row.original.tour;
    if (t == null) return '-';
    return typeof t === 'object' ? (t.name ?? '-') : String(t);
  },
  },
  {
    accessorKey: 'dateFrom',
    header: 'Ngày đi',
    cell: ({ row }) => new Date(row.getValue('dateFrom') as string).toLocaleDateString(),
  },
  {
    accessorKey: 'dateTo',
    header: 'Ngày về',
    cell: ({ row }) => new Date(row.getValue('dateTo') as string).toLocaleDateString(),
  },
  {
    accessorKey: 'availableSeats',
    header: 'Số chỗ',
  },
  {
    accessorKey: 'customers',
    header: 'Khách',
    cell: ({ row }) => {
      const raw = (row.original.customers ?? []) as any;

      // normalize to array: already array | { groups: [...] } | single customer object
      const customers = Array.isArray(raw)
        ? raw
        : raw && Array.isArray(raw.groups)
          ? raw.groups
          : raw
            ? [raw]
            : [];

      const total = customers.reduce((s: number, c: any) => {
        if (typeof c.numberOfPeople === 'number') return s + c.numberOfPeople;
        if (typeof c.totalPeople === 'number') return s + c.totalPeople;
        if (Array.isArray(c.members)) return s + c.members.length;
        const adults = c.totalAdults ?? c.adults ?? 0;
        const children = c.totalChildren ?? c.children ?? 0;
        const babies = c.totalBabies ?? c.babies ?? 0;
        return s + adults + children + babies;
      }, 0);

      return `${total} khách`;
    },
  },
  {
    accessorKey: 'availableSeats',
    header: 'Còn trống',
    cell: ({ row }) => row.getValue('availableSeats') || '-',
  },
  {
    accessorKey: 'status',
    header: 'Trạng thái',
    cell: ({ row }) => {
      const s = row.getValue('status') as TourBooking['status'];
      return (
        <Badge variant={s === 'pending' ? 'secondary' : s === 'completed' ? 'default' : 'destructive'}>
          {s}
        </Badge>
      );
    },
  },
  {
    accessorKey: 'createdAt',
    header: 'Ngày tạo',
    cell: ({ row }) => new Date(row.getValue('createdAt') as string).toLocaleString(),
  },
  {
    id: 'actions',
    cell: ({ row, table }) => {
      const booking = row.original;
      return (
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={() => (table.options.meta as any)?.onView(booking)}>Xem</Button>
          <Button size="sm" variant="outline" onClick={() => (table.options.meta as any)?.onUpdateStatus(booking)}>Cập nhật</Button>
        </div>
      );
    },
  },
];

export default function AdminTourBooking() {
  const [selectedBooking, setSelectedBooking] = useState<TourBooking | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const { data: bookings = [], isLoading } = useQuery({
    queryKey: ['tourBookings'],
    queryFn: async () => {
      const res = await getAllBookings();
      if (!res.success) throw new Error('Failed to fetch');
      return (res.data as unknown) as TourBooking[];
    },
  });

  const handleView = (b: TourBooking) => {
    setSelectedBooking(b);
    setIsDialogOpen(true);
  };

  const handleUpdateStatus = async (b: TourBooking) => {
    // simple status cycle: pending -> completed -> cancelled
    const next = b.status === 'pending' ? 'completed' : b.status === 'completed' ? 'cancelled' : 'pending';
    await fetch(`/api/tour-booking/${b._id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: next }),
    });
    // refresh
    window.location.reload();
  };

  if (isLoading) return <div className="h-[300px] flex items-center justify-center">Đang tải...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">Quản lý Booking Tour</h1>
        <p className="text-xs text-slate-400 font-semibold mt-1">Danh sách các tour đã đặt</p>
      </div>

      <DataTable
        columns={columns}
        data={bookings}
        searchKey="tour"
        searchPlaceholder="Tìm theo tour..."
        meta={{ onView: handleView, onUpdateStatus: handleUpdateStatus }}
      />

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Chi tiết Booking</DialogTitle>
          </DialogHeader>

          {selectedBooking && (
            <div className="space-y-6">
              <div>
                <h3 className="mb-2 font-semibold">Thông tin tour</h3>
                <div className="rounded-lg border p-4">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Tour:</span>
                    <span className="font-medium">{typeof selectedBooking.tour === 'object' ? selectedBooking.tour.name : selectedBooking.tour}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Thời gian:</span>
                    <span className="font-medium">{new Date(selectedBooking.dateFrom).toLocaleDateString()} → {new Date(selectedBooking.dateTo).toLocaleDateString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Số chỗ:</span>
                    <span className="font-medium">{selectedBooking.availableSeats}</span>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="mb-2 font-semibold">Khách hàng</h3>
                <div className="space-y-3">
                  {selectedBooking.customers.map((c, idx) => (
                    <div key={idx} className="rounded-lg border p-4">
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <div className="text-muted-foreground">Tên:</div>
                          <div className="font-medium">{c.fullname}</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">SĐT:</div>
                          <div className="font-medium">{c.phone}</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Email:</div>
                          <div className="font-medium">{c.email || '-'} </div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Người:</div>
                          <div className="font-medium">{c.numberOfPeople} (Ng: {c.adults} - Tr: {c.children} - Em: {c.babies})</div>
                        </div>
                        <div className="col-span-2">
                          <div className="text-muted-foreground">Trạng thái thanh toán:</div>
                          <div className="font-medium">{c.paymentStatus}</div>
                        </div>
                        {c.notes && (
                          <div className="col-span-2">
                            <div className="text-muted-foreground">Ghi chú:</div>
                            <div className="font-medium">{c.notes}</div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {selectedBooking.note && (
                <div>
                  <h3 className="mb-2 font-semibold">Ghi chú booking</h3>
                  <div className="rounded-lg border p-4">{selectedBooking.note}</div>
                </div>
              )}

              <Separator />

              <div className="flex gap-2">
                <Button onClick={() => handleUpdateStatus(selectedBooking)}>Chuyển trạng thái</Button>
                <Button variant="destructive" onClick={async () => { await fetch(`/api/tour-booking/${selectedBooking._id}`, { method: 'DELETE' }); window.location.reload(); }}>Hủy booking</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
