'use client';

import { register, sendEmailVerification } from '@/lib/actions/auth.actions';
import { login } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import { authFormSchema } from '@/schemas/auth.schema';
import { zodResolver } from '@hookform/resolvers/zod';
import { Loader2, Compass } from 'lucide-react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import z from 'zod';
import OTPModal from './modals/otp-modal';
import { Button } from './ui/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from './ui/form';
import GoogleLoginButton from './ui/google-button';
import { Input } from './ui/input';

export type FormType = 'sign-in' | 'sign-up';

const AuthForm = ({ type }: { type: FormType }) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Get redirect URL from query params (set by login-prompt-dialog)
  const redirectUrl = searchParams.get('redirect');

  const formSchema = authFormSchema(type);
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: '',
      username: '',
      password: '',
      confirmPassword: '',
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    const result =
      type === 'sign-up'
        ? await register(values)
        : await login({ email: values.email, password: values.password });
    if( result.success && result?.data?.isBlocked == true) {
      toast.error("Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên để biết thêm chi tiết.");
      return;
    }
    if (type === 'sign-in' && result.success) {
      setAuthState(result.data || null);
      // Use redirect URL if provided, otherwise default to admin/home
      const destination =
        redirectUrl || (result.data?.role === 'admin' ? '/admin' : '/');
      router.push(destination);
      return;
    }

    if (!result.success) {
      toast.error(result.message);
    }

    // Handle email verification for both login error and register success
    const needsVerification =
      ('code' in result && result.code === 'EMAIL_NOT_VERIFIED') ||
      (result.data && !result.data.isVerified);

    if (needsVerification) {
      const res = await sendEmailVerification({ email: values.email });
      toast[res.success ? 'success' : 'error'](res.message);
      if (res.success) setIsModalOpen(true);
    }
  };

  const setAuthState = (user: User | null) => {
    useAuthStore.getState().setUser(user);
  };

  return (
    <div className="relative">
      {/* Form Container */}
      <div className="space-y-6">
        {/* Header */}
        <div className="space-y-2 text-center">
          <h1 className="text-3xl font-bold tracking-tight">
            {type === 'sign-in' ? 'Chào mừng trở lại' : 'Tạo tài khoản'}
          </h1>
          <p className="text-muted-foreground">
            {type === 'sign-in'
              ? 'Đăng nhập để tiếp tục khám phá'
              : 'Bắt đầu hành trình cắm trại của bạn'}
          </p>
        </div>

        {/* Form */}
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            {/* Email Field */}
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="you@example.com"
                      type="email"
                      disabled={isLoading}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Username Field (Sign Up Only) */}
            {type === 'sign-up' && (
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Tên người dùng</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="johndoe"
                        disabled={isLoading}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {/* Password Field */}
            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Mật khẩu</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="••••••••"
                      type="password"
                      disabled={isLoading}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Confirm Password Field (Sign Up Only) */}
            {type === 'sign-up' && (
              <FormField
                control={form.control}
                name="confirmPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Xác nhận mật khẩu</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="••••••••"
                        type="password"
                        disabled={isLoading}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {/* Forgot Password Link (Sign In Only) */}
            {type === 'sign-in' && (
              <div className="flex justify-end">
                <Link
                  href="/forgot-password"
                  className="text-primary text-sm hover:underline"
                >
                  Quên mật khẩu?
                </Link>
              </div>
            )}

            {/* Submit Button */}
            <Button type="submit" className="h-11 w-full" disabled={isLoading}>
              {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {type === 'sign-in' ? 'Đăng Nhập' : 'Đăng Ký'}
            </Button>

            {/* Divider */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background text-muted-foreground px-2">
                  Hoặc tiếp tục với
                </span>
              </div>
            </div>

            {/* Google Login Button */}
            <GoogleLoginButton
              onAuthSuccess={user => setAuthState(user)}
              redirectUrl={redirectUrl || undefined}
            />

            {/* Back to Guest Page Button */}
            <Button
              type="button"
              variant="outline"
              className="h-11 w-full cursor-pointer flex items-center justify-center gap-2 border-primary/20 hover:bg-primary/5 hover:text-primary transition-all duration-200"
              onClick={() => router.push('/')}
            >
              <Compass className="h-4 w-4" />
              Vào trang khách
            </Button>
          </form>
        </Form>

        {/* Footer Links */}
        <div className="space-y-2 text-center">
          <p className="text-muted-foreground text-sm">
            {type === 'sign-in'
              ? 'Bạn chưa có tài khoản?'
              : 'Bạn đã có tài khoản?'}
          </p>
          <Link
            href={type === 'sign-in' ? '/sign-up' : '/sign-in'}
            className="text-primary block text-sm font-medium hover:underline"
          >
            {type === 'sign-in' ? 'Đăng ký ngay' : 'Đăng nhập ngay'}
          </Link>
        </div>
      </div>

      <OTPModal
        email={form.getValues('email')}
        type="verification"
        isOpenFromParent={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </div>
  );
};

export default AuthForm;
