'use client';

import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { updateProfile, uploadMedia } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation } from '@tanstack/react-query';

import { Camera, Loader2, Save } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useRef, useState } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { z } from 'zod';

const profileFormSchema = z.object({
  username: z
    .string()
    .min(3, 'Tên người dùng phải có ít nhất 3 ký tự')
    .max(30, 'Tên người dùng không được quá 30 ký tự')
    .regex(
      /^[a-zA-Z0-9_]+$/,
      'Tên người dùng chỉ được chứa chữ cái, số và dấu gạch dưới',
    ),
  bio: z.string().max(500, 'Tiểu sử không được quá 500 ký tự').optional(),
});

type ProfileFormValues = z.infer<typeof profileFormSchema>;

export default function EditProfilePage() {
  const router = useRouter();
  const { user, setUser } = useAuthStore();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | undefined>(
    user?.avatarUrl || undefined,
  );
  const [uploadingAvatar, setUploadingAvatar] = useState(false);

  const form = useForm<ProfileFormValues>({
    resolver: zodResolver(profileFormSchema),
    defaultValues: {
      username: user?.username || '',
      bio: '',
    },
  });

  const updateProfileMutation = useMutation({
    mutationFn: async (
      data: Partial<{ username: string; bio: string; avatar: string }>,
    ) => {
     
      return updateProfile(data);
    },
    onSuccess: response => {
      if ('data' in response && response.data) {
        const userData = response.data as User;
        setUser(userData);
        toast.success('Cập nhật thông tin thành công!');
        router.push(`/u/${userData.username}/trips`);
      }
    },
    onError: () => {
      toast.error('Có lỗi xảy ra khi cập nhật thông tin');
    },
  });

  const handleAvatarChange = async (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Preview
    const reader = new FileReader();
    reader.onloadend = () => {
      setAvatarPreview(reader.result as string);
    };
    reader.readAsDataURL(file);

    // Upload
    setUploadingAvatar(true);
    try {
      const formData = new FormData();
      formData.append('files', file);
      const response: any = await uploadMedia(formData);
      console.log("Upload media response:", response); 
      if (response.success)  {
        
        await updateProfile({ avatar: response.data[0] });
        toast.success('Cập nhật ảnh đại diện thành công!');
      }
    } catch {
      toast.error('Có lỗi xảy ra khi tải ảnh lên');
      setAvatarPreview(user?.avatarUrl || undefined);
    } finally {
      setUploadingAvatar(false);
    }
  };

  const onSubmit = (data: ProfileFormValues) => {
    updateProfileMutation.mutate(data);
  };

  if (!user) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <p>Vui lòng đăng nhập để chỉnh sửa thông tin</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      <Card>
        <CardHeader>
          <CardTitle>Chỉnh sửa hồ sơ</CardTitle>
          <CardDescription>
            Cập nhật thông tin cá nhân của bạn. Những thông tin này sẽ được hiển
            thị công khai.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Avatar Section */}
          <div className="flex items-center gap-6">
            <div className="relative">
              <Avatar className="h-24 w-24">
                <AvatarImage src={avatarPreview} alt={user.username} />
                <AvatarFallback className="text-2xl">
                  {user.username?.charAt(0).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploadingAvatar}
                className="absolute right-0 bottom-0 rounded-full bg-primary p-2 text-white transition-colors hover:bg-primary/90 disabled:opacity-50 cursor-pointer"
              >
                {uploadingAvatar ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Camera className="h-4 w-4" />
                )}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleAvatarChange}
                className="hidden"
              />
            </div>
            <div>
              <h3 className="font-medium">Ảnh đại diện</h3>
              <p className="text-muted-foreground text-sm">
                Nhấn vào biểu tượng camera để thay đổi ảnh đại diện
              </p>
            </div>
          </div>

          {/* Profile Form */}
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Tên người dùng</FormLabel>
                    <FormControl>
                      <Input placeholder="username" {...field} />
                    </FormControl>
                    <FormDescription>
                      Đây là tên hiển thị công khai của bạn. Bạn có thể thay đổi
                      bất cứ lúc nào.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="bio"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Tiểu sử</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="Giới thiệu về bản thân bạn..."
                        className="resize-none"
                        rows={4}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      Chia sẻ một chút về bản thân để những người cắm trại khác
                      biết về bạn.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="flex items-center gap-4">
                <Button
                  type="submit"
                  className="bg-primary hover:bg-primary/90 cursor-pointer"
                  disabled={updateProfileMutation.isPending}
                >
                  {updateProfileMutation.isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Đang lưu...
                    </>
                  ) : (
                    <>
                      <Save className="mr-2 h-4 w-4" />
                      Lưu thay đổi
                    </>
                  )}
                </Button>
                <Button type="button" variant="outline" asChild>
                  <Link href={`/u/${user.username}/trips`}>Hủy</Link>
                </Button>
              </div>
            </form>
          </Form>

          {/* Change Password Link */}
          <div className="border-t pt-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-medium">Đổi mật khẩu</h3>
                <p className="text-muted-foreground text-sm">
                  Cập nhật mật khẩu để bảo mật tài khoản của bạn
                </p>
              </div>
              <Button variant="outline" asChild>
                <Link href="/u/edit-password">Đổi mật khẩu</Link>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
