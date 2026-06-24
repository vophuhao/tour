'use client';

import { useEffect, useState } from 'react';
import Script from 'next/script';
import { Globe, Check } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';

export default function GoogleTranslator() {
  const [currentLang, setCurrentLang] = useState<'vi' | 'en'>('vi');

  useEffect(() => {
    // Check cookie on mount
    const getGoogtrans = () => {
      const cookies = document.cookie.split(';');
      const googtransCookie = cookies.find(c => c.trim().startsWith('googtrans='));
      if (googtransCookie) {
        const val = googtransCookie.split('=')[1];
        if (val.includes('/en')) {
          return 'en' as const;
        }
      }
      return 'vi' as const;
    };
    setCurrentLang(getGoogtrans());
  }, []);

  const changeLanguage = (lang: 'vi' | 'en') => {
    const domain = window.location.hostname;
    // Set google translate cookie format
    if (lang === 'en') {
      document.cookie = "googtrans=/vi/en; path=/; domain=" + domain;
      document.cookie = "googtrans=/vi/en; path=/;";
    } else {
      document.cookie = "googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=" + domain;
      document.cookie = "googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
      document.cookie = "googtrans=/vi/vi; path=/; domain=" + domain;
      document.cookie = "googtrans=/vi/vi; path=/;";
    }
    setCurrentLang(lang);
    window.location.reload();
  };

  return (
    <>
      <div id="google_translate_element" style={{ display: 'none', position: 'absolute', top: '-9999px' }} />
      <Script
        src="https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"
        strategy="afterInteractive"
      />
      <Script id="google-translate-init" strategy="afterInteractive">
        {`
          window.googleTranslateElementInit = function() {
            new window.google.translate.TranslateElement({
              pageLanguage: 'vi',
              includedLanguages: 'en,vi',
              autoDisplay: false
            }, 'google_translate_element');
          }
        `}
      </Script>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button 
            variant="ghost" 
            size="icon" 
            className="h-9 w-9 rounded-xl border border-slate-200 dark:border-slate-800 bg-background/50 hover:bg-slate-100 dark:hover:bg-slate-900 cursor-pointer"
          >
            <Globe className="h-4 w-4 text-slate-650 dark:text-slate-350" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-36 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 p-1.5 shadow-xl">
          <DropdownMenuItem
            onClick={() => changeLanguage('vi')}
            className="flex items-center justify-between text-xs font-bold px-3 py-2 rounded-lg cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900"
          >
            <span className="flex items-center gap-2">
              <span className="text-sm">🇻🇳</span> Tiếng Việt
            </span>
            {currentLang === 'vi' && <Check className="h-3.5 w-3.5 text-primary" />}
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => changeLanguage('en')}
            className="flex items-center justify-between text-xs font-bold px-3 py-2 rounded-lg cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900"
          >
            <span className="flex items-center gap-2">
              <span className="text-sm">🇺🇸</span> English
            </span>
            {currentLang === 'en' && <Check className="h-3.5 w-3.5 text-primary" />}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
