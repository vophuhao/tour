import ChatbotWrapper from '@/components/chatbot-wrapper';
import Footer from '@/components/footer';
import Header from '@/components/Header';
import ChatModal from '@/components/modals/chatModal';
import { CompareDrawer } from '@/components/property/CompareDrawer';
import { Suspense } from 'react';

// Header loading fallback
function HeaderSkeleton() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/95 backdrop-blur">
      <div className="mx-auto max-w-7xl px-4">
        <div className="flex h-16 items-center justify-between">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="hidden gap-6 md:flex">
            {[...Array(5)].map((_, i) => (
              <div
                key={i}
                className="h-4 w-16 animate-pulse rounded bg-muted"
              />
            ))}
          </div>
          <div className="flex gap-3">
            <div className="h-10 w-10 animate-pulse rounded bg-muted" />
            <div className="hidden h-10 w-24 animate-pulse rounded bg-muted md:block" />
          </div>
        </div>
      </div>
    </header>
  );
}

export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Suspense fallback={<HeaderSkeleton />}>
        <Header />
      </Suspense>
      {children}
      <Footer />

      <ChatModal />

      <ChatbotWrapper />

      <CompareDrawer />
    </>
  );
}
