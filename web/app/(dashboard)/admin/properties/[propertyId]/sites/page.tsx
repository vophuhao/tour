'use client';

import { DataTable } from '@/components/admin/data-table';
import { DeleteAlertDialog } from '@/components/modals/delete-alert-dialog';
import { SiteModal } from '@/components/modals/site-modal';
import {
  deleteSite,
  getPropertyById,
  getSitesByProperty,
} from '@/lib/client-actions';
import { Property, Site } from '@/types/property-site';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Building2 } from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { columns } from './columns';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function PropertySitesPage() {
  const params = useParams();
  const router = useRouter();
  const propertyId = params.propertyId as string;

  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedSite, setSelectedSite] = useState<Site | null>(null);

  // Fetch property details
  const { data: property } = useQuery({
    queryKey: ['property', propertyId],
    queryFn: () =>
      getPropertyById(propertyId).then(res => res.data as Property),
    enabled: !!propertyId,
  });

  // Fetch sites for this property
  const { data: sites = [], refetch } = useQuery({
    queryKey: ['property-sites', propertyId],
    queryFn: () => getSitesByProperty(propertyId).then(res => res.data || []),
    enabled: !!propertyId,
  });

  const handleCreate = () => {
    setCreateModalOpen(true);
  };

  const handleEdit = (site: Site) => {
    setSelectedSite(site);
    setEditModalOpen(true);
  };

  const handleDelete = (site: Site) => {
    setSelectedSite(site);
    setDeleteDialogOpen(true);
  };

  const handleConfirmDelete = async () => {
    if (!selectedSite) return;

    const res: any = await deleteSite(selectedSite._id);

    if (!res.success) {
      toast.error(res.message || 'Xóa site thất bại');
    } else {
      toast.success(res.message || 'Xóa site thành công');
      refetch();
      setDeleteDialogOpen(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header with back button */}
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => router.push('/admin/properties')}
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
            Quản lý Sites
          </h1>
          {property && (
            <p className="text-xs text-slate-400 font-semibold mt-1 flex items-center gap-2">
              <Building2 className="h-4 w-4" />
              {property.name}
            </p>
          )}
        </div>
      </div>

      {/* Property Info Card */}
      {property && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Thông tin Property</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-3">
            <div>
              <p className="text-muted-foreground text-sm">Địa chỉ</p>
              <p className="font-medium">
                {property.location.address}, {property.location.city}
              </p>
            </div>
            <div>
              <p className="text-muted-foreground text-sm">Loại Property</p>
              <p className="font-medium capitalize">
                {property.propertyType?.replace('-', ' ')}
              </p>
            </div>
            <div>
              <p className="text-muted-foreground text-sm">Số Sites</p>
              <p className="font-medium">{sites.length} sites</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Sites DataTable */}
      <DataTable
        columns={columns}
        data={sites}
        searchKey="name"
        searchPlaceholder="Tìm kiếm site..."
        createButton={{
          label: 'Tạo Site',
          onClick: handleCreate,
        }}
        meta={{
          onEdit: handleEdit,
          onDelete: handleDelete,
        }}
      />

      {/* Create Modal */}
      <SiteModal
        open={createModalOpen}
        onOpenChange={setCreateModalOpen}
        propertyId={propertyId}
        onSuccess={() => {
          refetch();
          setCreateModalOpen(false);
        }}
      />

      {/* Edit Modal */}
      <SiteModal
        open={editModalOpen}
        onOpenChange={setEditModalOpen}
        propertyId={propertyId}
        site={selectedSite}
        onSuccess={() => {
          refetch();
          setEditModalOpen(false);
        }}
      />

      {/* Delete Dialog */}
      <DeleteAlertDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Xóa site?"
        description={`Bạn có chắc chắn muốn xóa site "${selectedSite?.name}"? Hành động này không thể hoàn tác.`}
        onConfirm={handleConfirmDelete}
      />
    </div>
  );
}
