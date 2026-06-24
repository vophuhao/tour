import { CompareClient } from './CompareClient';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'So sánh địa điểm cắm trại | Campo',
  description: 'So sánh song song các địa điểm cắm trại để tìm ra lựa chọn hoàn hảo nhất cho chuyến đi của bạn.',
};

interface ComparePageProps {
  searchParams: Promise<{
    ids?: string;
  }>;
}

export default async function ComparePage({ searchParams }: ComparePageProps) {
  const params = await searchParams;
  const initialIds = params.ids || '';

  return (
    <main className="min-h-screen bg-background">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        <CompareClient initialIds={initialIds} />
      </div>
    </main>
  );
}
