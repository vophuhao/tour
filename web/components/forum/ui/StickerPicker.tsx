/* eslint-disable @next/next/no-img-element */
import React, { useState, useEffect, useRef } from 'react';
import { Search, TrendingUp, Loader2, X } from 'lucide-react';
import { giphyApi, GiphyImage } from '../../../lib/giphy';
import "../style/StickerPicker.css";

interface StickerPickerProps {
  onSelect: (gifUrl: string) => void;
  onClose: () => void;
  anchor?: { top: number; left: number };
}

const FALLBACK_STICKERS: GiphyImage[] = [
  { id: 'fb1', title: 'Grinning Face', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Face.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Face.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Face.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Face.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Face.webp', width: '100', height: '100' } } },
  { id: 'fb2', title: 'Grinning Squinting', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Squinting%20Face.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Squinting%20Face.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Squinting%20Face.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Squinting%20Face.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Grinning%20Squinting%20Face.webp', width: '100', height: '100' } } },
  { id: 'fb3', title: 'Halo', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Halo.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Halo.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Halo.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Halo.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Halo.webp', width: '100', height: '100' } } },
  { id: 'fb4', title: 'Heart Eyes', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Heart-Eyes.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Heart-Eyes.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Heart-Eyes.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Heart-Eyes.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20with%20Heart-Eyes.webp', width: '100', height: '100' } } },
  { id: 'fb5', title: 'Kissing', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Face%20Blowing%20a%20Kiss.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Face%20Blowing%20a%20Kiss.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Face%20Blowing%20a%20Kiss.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Face%20Blowing%20a%20Kiss.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Face%20Blowing%20a%20Kiss.webp', width: '100', height: '100' } } },
  { id: 'fb6', title: 'Tongue', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Squinting%20Face%20with%20Tongue.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Squinting%20Face%20with%20Tongue.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Squinting%20Face%20with%20Tongue.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Squinting%20Face%20with%20Tongue.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Squinting%20Face%20with%20Tongue.webp', width: '100', height: '100' } } },
  { id: 'fb7', title: 'Zany', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Zany%20Face.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Zany%20Face.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Zany%20Face.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Zany%20Face.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Zany%20Face.webp', width: '100', height: '100' } } },
  { id: 'fb8', title: 'Shushing', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Shushing%20Face.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Shushing%20Face.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Shushing%20Face.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Shushing%20Face.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Shushing%20Face.webp', width: '100', height: '100' } } },
  { id: 'fb9', title: 'Thinking', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Thinking%20Face.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Thinking%20Face.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Thinking%20Face.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Thinking%20Face.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Thinking%20Face.webp', width: '100', height: '100' } } },
  { id: 'fb10', title: 'Exploding', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Exploding%20Head.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Exploding%20Head.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Exploding%20Head.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Exploding%20Head.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Exploding%20Head.webp', width: '100', height: '100' } } },
  { id: 'fb11', title: 'Partying', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Partying%20Face.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Partying%20Face.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Partying%20Face.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Partying%20Face.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Partying%20Face.webp', width: '100', height: '100' } } },
  { id: 'fb12', title: 'Sunglasses', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20With%20Sunglasses.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20With%20Sunglasses.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20With%20Sunglasses.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20With%20Sunglasses.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Smiling%20Face%20With%20Sunglasses.webp', width: '100', height: '100' } } },
  { id: 'fb13', title: 'Ghost', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Ghost.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Ghost.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Ghost.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Ghost.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Smileys/Ghost.webp', width: '100', height: '100' } } },
  { id: 'fb14', title: 'Heart', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Symbols/Red%20Heart.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Symbols/Red%20Heart.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Symbols/Red%20Heart.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Symbols/Red%20Heart.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Symbols/Red%20Heart.webp', width: '100', height: '100' } } },
  { id: 'fb15', title: 'Fire', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Animals%20and%20Nature/Fire.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Animals%20and%20Nature/Fire.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Animals%20and%20Nature/Fire.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Animals%20and%20Nature/Fire.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Animals%20and%20Nature/Fire.webp', width: '100', height: '100' } } },
  { id: 'fb16', title: 'Sparkles', url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Special%20Characters/Sparkles.webp', images: { fixed_height: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Special%20Characters/Sparkles.webp', width: '100', height: '100' }, fixed_height_small: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Special%20Characters/Sparkles.webp', width: '80', height: '80' }, original: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Special%20Characters/Sparkles.webp', width: '150', height: '150' }, downsized: { url: 'https://raw.githubusercontent.com/Tarikul-Islam-Anik/Telegram-Animated-Emojis/main/Special%20Characters/Sparkles.webp', width: '100', height: '100' } } }
];

const StickerPicker: React.FC<StickerPickerProps> = ({ onSelect, onClose, anchor }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [stickers, setStickers] = useState<GiphyImage[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'trending' | 'search'>('trending');
  const [pickerPosition, setPickerPosition] = useState<React.CSSProperties>({});
  const pickerRef = useRef<HTMLDivElement>(null);
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Load trending stickers on mount
  useEffect(() => {
    loadTrending();
  }, []);

  // Calculate and update picker position when anchor changes or window resizes
  useEffect(() => {
    if (!anchor) {
      setPickerPosition({});
      return;
    }

    const calculatePosition = () => {
      const isMobile = window.innerWidth <= 768;
      const isTablet = window.innerWidth > 768 && window.innerWidth <= 1024;

      // Sidebar width: 380px on desktop, 80px when collapsed, 0 on mobile
      let sidebarOffset = 0;
      if (!isMobile) {
        // Check if sidebar is collapsed (could be 80px) or normal (380px)
        const sidebar = document.querySelector('.chat-sidebar');
        if (sidebar) {
          sidebarOffset = sidebar.classList.contains('collapsed') ? 80 : 380;
        } else {
          // Fallback: assume sidebar exists
          sidebarOffset = isTablet ? 320 : 380;
        }
      }

      // Calculate left position: ensure it doesn't overlap with sidebar
      const pickerWidth = window.innerWidth <= 480 ? Math.min(360, window.innerWidth - 24) : 360;
      const buttonLeft = anchor.left;
      const minLeft = sidebarOffset + 20; // 20px margin from sidebar
      const maxLeft = window.innerWidth - pickerWidth - 20; // 20px margin from right edge

      let calculatedLeft = buttonLeft - (pickerWidth / 2); // Try to center on button
      calculatedLeft = Math.max(minLeft, Math.min(calculatedLeft, maxLeft));

      // Calculate top position
      const pickerHeight = window.innerWidth <= 480 ? 420 : 500;
      const calculatedTop = Math.max(20, anchor.top - pickerHeight - 10); // 10px gap above button

      setPickerPosition({
        position: 'fixed',
        top: `${calculatedTop}px`,
        left: `${calculatedLeft}px`,
        zIndex: 10000,
      });
    };

    calculatePosition();

    // Update position on window resize
    const handleResize = () => calculatePosition();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [anchor]);

  // Close when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [onClose]);

  const loadTrending = async () => {
    setLoading(true);
    try {
      const data = await giphyApi.getTrending(30);
      if (data && data.length > 0) {
        setStickers(data);
      } else {
        setStickers(FALLBACK_STICKERS);
      }
      setActiveTab('trending');
    } catch (error) {
      console.error('Failed to load trending:', error);
      setStickers(FALLBACK_STICKERS);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async (query: string) => {
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    if (!query.trim()) {
      loadTrending();
      setActiveTab('trending');
      return;
    }

    searchTimeoutRef.current = setTimeout(async () => {
      setLoading(true);
      try {
        const data = await giphyApi.search(query.trim(), 30, 0);
        setStickers(data);
        setActiveTab('search');
      } catch (error) {
        console.error('Search failed:', error);
      } finally {
        setLoading(false);
      }
    }, 500); // Debounce 500ms
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setSearchQuery(value);
    handleSearch(value);
  };

  const handleSelect = (gif: GiphyImage) => {
    // Sử dụng URL chất lượng cao để gửi
    const url = giphyApi.getImageUrl(gif, 'medium');
    onSelect(url);
    onClose();
  };

  return (
    <div className="sticker-picker-portal" style={pickerPosition} ref={pickerRef}>
      <div className="sticker-picker">
        {/* Header */}
        <div className="sticker-picker-header">
          <h3>Nhãn dán & GIF</h3>
          <button className="sticker-picker-close" onClick={onClose} title="Đóng">
            <X size={18} />
          </button>
        </div>

        {/* Search Bar */}
        <div className="sticker-picker-search">
          <Search size={18} />
          <input
            type="text"
            placeholder="Tìm kiếm nhãn dán..."
            value={searchQuery}
            onChange={handleSearchChange}
            autoFocus
          />
          {searchQuery && (
            <button
              className="sticker-picker-clear-search"
              onClick={() => {
                setSearchQuery('');
                loadTrending();
              }}
              title="Xóa"
            >
              <X size={16} />
            </button>
          )}
        </div>

        {/* Tabs */}
        <div className="sticker-picker-tabs">
          <button
            className={`sticker-picker-tab ${activeTab === 'trending' ? 'active' : ''}`}
            onClick={() => {
              setSearchQuery('');
              loadTrending();
            }}
          >
            <TrendingUp size={16} />
            <span>Đang thịnh hành</span>
          </button>
          {searchQuery && (
            <button
              className={`sticker-picker-tab ${activeTab === 'search' ? 'active' : ''}`}
              disabled
            >
              <Search size={16} />
              <span>Kết quả tìm kiếm</span>
            </button>
          )}
        </div>

        {/* Stickers Grid */}
        <div className="sticker-picker-content">
          {loading && stickers.length === 0 ? (
            <div className="sticker-picker-loading">
              <Loader2 className="spinner" size={32} />
              <p>Đang tải...</p>
            </div>
          ) : stickers.length === 0 ? (
            <div className="sticker-picker-empty">
              <p>Không tìm thấy nhãn dán nào</p>
              <button onClick={loadTrending} className="sticker-picker-retry-btn">
                Xem đang thịnh hành
              </button>
            </div>
          ) : (
            <div className="sticker-picker-grid">
              {stickers.map((gif) => (
                <button
                  key={gif.id}
                  className="sticker-picker-item"
                  onClick={() => handleSelect(gif)}
                  title={gif.title}
                >
                  <img
                    src={giphyApi.getImageUrl(gif, 'small')}
                    alt={gif.title}
                    loading="lazy"
                  />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer Info */}
        <div className="sticker-picker-footer">
          <p>Powered by GIPHY</p>
        </div>
      </div>
    </div>
  );
};

export default StickerPicker;