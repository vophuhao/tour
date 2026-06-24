import axios, { AxiosError, AxiosResponse } from 'axios';
import { redirect } from 'next/navigation';
import { UNAUTHORIZED, FORBIDDEN } from './constants';
import { toast } from 'sonner';
import { logout } from './client-actions';

// cấu hình chung cho axios
const options = {
  baseURL: process.env.NEXT_PUBLIC_API_URL as string,
  withCredentials: true,
};

// client riêng cho refresh token để tránh loop
const TokenRefreshClient = axios.create(options);
TokenRefreshClient.interceptors.response.use(
  (response: AxiosResponse) => response.data,
);

const apiClient = axios.create(options);

apiClient.interceptors.response.use(
  (response: AxiosResponse) => response.data,
  async (error: AxiosError<ErrorResponse>) => {
    const { config: originalRequest, response } = error;
    const { status, data } = response || {};

    if (
      status === UNAUTHORIZED &&
      ['INVALID_ACCESS_TOKEN', 'TOKEN_EXPIRED'].includes(data?.code || '')
    ) {
      try {
        // refresh access token xong retry request cũ
        await TokenRefreshClient.get('/auth/refresh');
        if (originalRequest) {
          return TokenRefreshClient(originalRequest);
        }
      } catch (refreshError) {
        console.log('Refresh token failed: ', refreshError);
        if (typeof window !== 'undefined') {
          window.location.href = '/sign-in';
        } else {
          redirect('/sign-in');
        }

        return Promise.reject(refreshError);
      }
    }

    // Handle blocked account (403 FORBIDDEN)
    if (status === FORBIDDEN && data?.message?.includes('khóa')) {
      if (typeof window !== 'undefined') {
        toast.error('Tài khoản của bạn đã bị khóa');
        // Redirect to sign-in after a short delay
        const res = await logout();
        if (res.success) {
          window.location.href = '/sign-in';
        }
      } else {
        redirect('/sign-in');
      }
      return Promise.reject(data);
    }

    return Promise.reject({
      //status, // http status code
      ...data,
    });
  },
);

export default apiClient;
