'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import API from '@/lib/api-client';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  MapPin,
  Search,
  Calendar,
  Car,
  Sparkles,
  ArrowRight,
  Clock,
  Compass,
  Tent,
  ChevronRight,
  Info,
  Loader2,
  Navigation,
  Star
} from 'lucide-react';
import { format } from 'date-fns';

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN

interface PlaceSuggestion {
  id: string;
  place_name: string;
  center: [number, number]; // [lng, lat]
}

interface Campsite {
  _id: string;
  name: string;
  slug: string;
  propertyType: string;
  location: {
    address: string;
    city: string;
    state: string;
    coordinates?: { lat: number; lng: number };
  };
  pricing: {
    basePrice: number;
  };
  images?: string[];
  rating?: number;
  reviewCount?: number;
  stats?: {
    totalSites?: number;
  };
}

interface StopItinerary {
  dayNumber: number;
  fromName: string;
  toName: string;
  stopCoords: [number, number]; // [lng, lat]
  distanceKm: number;
  durationHrs: number;
  campsites: Campsite[];
  weather: string;
  aiTip: string;
}

export default function RoadtripPlannerPage() {
  const [origin, setOrigin] = useState('');
  const [originCoords, setOriginCoords] = useState<[number, number] | null>(null);
  const [originSuggestions, setOriginSuggestions] = useState<PlaceSuggestion[]>([]);
  const [showOriginSuggestions, setShowOriginSuggestions] = useState(false);

  const [destination, setDestination] = useState('');
  const [destinationCoords, setDestinationCoords] = useState<[number, number] | null>(null);
  const [destSuggestions, setDestSuggestions] = useState<PlaceSuggestion[]>([]);
  const [showDestSuggestions, setShowDestSuggestions] = useState(false);

  const [days, setDays] = useState(3);
  const [campingStyle, setCampingStyle] = useState('all');
  const [spotType, setSpotType] = useState('all');
  const [loading, setLoading] = useState(false);
  const [itinerary, setItinerary] = useState<StopItinerary[]>([]);
  const [routeInfo, setRouteInfo] = useState<{ totalDistance: number; totalDuration: number } | null>(null);

  const debounceTimer = useRef<NodeJS.Timeout | null>(null);

  const fetchSuggestions = async (query: string, type: 'origin' | 'dest') => {
    if (!query || query.length < 3) {
      if (type === 'origin') setOriginSuggestions([]);
      if (type === 'dest') setDestSuggestions([]);
      return;
    }

    try {
      const url = `https://api.mapbox.com/geocoding/v5/mapbox.places/${encodeURIComponent(query)}.json?access_token=${MAPBOX_TOKEN}&limit=5&country=vn&language=vi`;
      const res = await fetch(url);
      const data = await res.json();
      const features = (data.features ?? []).map((f: any) => ({
        id: f.id,
        place_name: f.place_name,
        center: f.center,
      }));

      if (type === 'origin') setOriginSuggestions(features);
      if (type === 'dest') setDestSuggestions(features);
    } catch (err) {
      console.error('Error fetching Mapbox Geocoding suggestions:', err);
    }
  };

  const handleInputChange = (val: string, type: 'origin' | 'dest') => {
    if (type === 'origin') {
      setOrigin(val);
      setOriginCoords(null);
      setShowOriginSuggestions(true);
    } else {
      setDestination(val);
      setDestinationCoords(null);
      setShowDestSuggestions(true);
    }

    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => {
      fetchSuggestions(val, type);
    }, 450);
  };

  const handleSelectSuggestion = (suggestion: PlaceSuggestion, type: 'origin' | 'dest') => {
    if (type === 'origin') {
      setOrigin(suggestion.place_name);
      setOriginCoords(suggestion.center);
      setOriginSuggestions([]);
      setShowOriginSuggestions(false);
    } else {
      setDestination(suggestion.place_name);
      setDestinationCoords(suggestion.center);
      setDestSuggestions([]);
      setShowDestSuggestions(false);
    }
  };

  const handlePlanRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!originCoords || !destinationCoords) {
      toast.error('Vui lòng chọn địa điểm từ danh sách gợi ý!');
      return;
    }

    setLoading(true);
    try {
      const directionsUrl = `https://api.mapbox.com/directions/v5/mapbox/driving/${originCoords[0]},${originCoords[1]};${destinationCoords[0]},${destinationCoords[1]}?geometries=geojson&access_token=${MAPBOX_TOKEN}`;
      const routeRes = await fetch(directionsUrl);
      const routeData = await routeRes.json();

      if (!routeData.routes || routeData.routes.length === 0) {
        toast.error('Không thể tìm thấy lộ trình đường bộ phù hợp!');
        setLoading(false);
        return;
      }

      const route = routeData.routes[0];
      const totalDistance = Math.round(route.distance / 1000);
      const totalDuration = Math.round(route.duration / 3600);
      setRouteInfo({ totalDistance, totalDuration });

      const coordinates: [number, number][] = route.geometry.coordinates;
      const totalPoints = coordinates.length;

      const stops: StopItinerary[] = [];
      const segmentSize = Math.floor(totalPoints / days);

      const weatherOptions = ['Nắng nhẹ, thời tiết mát mẻ 🌤️', 'Nhiệt độ hạ dần về đêm, trời quang mây 🌌', 'Có sương mù sáng sớm, mát lạnh 🌫️', 'Không mưa, gió mát thuận lợi 🍃'];
      const aiTipsList = [
        'AI khuyên bạn: Chặng đường đi bắt đầu leo dốc, hãy kiểm tra kỹ áp suất lốp trước khi khởi hành.',
        'AI khuyên bạn: Nên cắm trại trước 17:00 chiều để chuẩn bị củi đốt và tránh sương mù bao phủ thung lũng.',
        'AI khuyên bạn: Khu vực này có view bình minh rất đẹp, hãy dựng lều quay về hướng Đông để đón tia nắng đầu ngày.',
        'AI khuyên bạn: Chặng lái xe hôm nay kéo dài qua rừng thông, hãy chuẩn bị bình giữ nhiệt ấm và đồ ăn nhẹ.'
      ];

      for (let d = 1; d <= days; d++) {
        let toName = '';
        let stopCoords: [number, number];

        if (d === days) {
          toName = destination.split(',')[0];
          stopCoords = destinationCoords;
        } else {
          const index = d * segmentSize;
          stopCoords = coordinates[index];
          try {
            const geocodeUrl = `https://api.mapbox.com/geocoding/v5/mapbox.places/${stopCoords[0]},${stopCoords[1]}.json?access_token=${MAPBOX_TOKEN}&types=place,locality`;
            const geoRes = await fetch(geocodeUrl);
            const geoData = await geoRes.json();
            toName = geoData.features?.[0]?.text || `Trạm dừng chân ${d}`;
          } catch {
            toName = `Trạm dừng chân ${d}`;
          }
        }

        const fromName = d === 1 ? origin.split(',')[0] : stops[d - 2].toName;
        const distanceKm = Math.round(totalDistance / days);
        const durationHrs = Number((totalDuration / days).toFixed(1));

        let campsites: Campsite[] = [];
        let paidCampsites: Campsite[] = [];
        let freeCampsites: Campsite[] = [];

        // 1. Fetch paid spots if spotType is 'all' or 'paid'
        if (spotType === 'all' || spotType === 'paid') {
          try {
            const searchRes = await API.post('/properties/route-search', {
              points: [stopCoords],
              radius: 40,
              campingStyle: campingStyle !== 'all' ? [campingStyle] : undefined,
              limit: 3,
              sortBy: 'rating'
            });

            if (searchRes.data && Array.isArray(searchRes.data)) {
              paidCampsites = searchRes.data.map((p: any) => ({
                _id: p._id,
                name: p.name,
                slug: p.slug,
                propertyType: p.propertyType,
                location: p.location,
                pricing: p.pricing || { basePrice: p.minPrice || 500000 },
                images: p.images || (p.photos ? p.photos.map((ph: any) => ph.url) : []),
                rating: (p.rating && typeof p.rating === 'object' && typeof p.rating.average === 'number')
                  ? p.rating.average
                  : (typeof p.rating === 'number'
                    ? p.rating
                    : (p.stats?.averageRating || 4.8)),
                reviewCount: (p.rating && typeof p.rating === 'object' && typeof p.rating.count === 'number')
                  ? p.rating.count
                  : (typeof p.stats?.totalReviews === 'number'
                    ? p.stats.totalReviews
                    : 12),
                stats: p.stats
              }));
            }
          } catch (searchErr) {
            console.error(`Error searching properties at stop ${d}:`, searchErr);
          }
        }

        // 2. Fetch free spots if spotType is 'all' or 'free'
        if (spotType === 'all' || spotType === 'free') {
          try {
            const freeRes = await API.get('/free-spots/nearby', {
              params: {
                lat: stopCoords[1],
                lng: stopCoords[0],
                radius: 40 // 40km radius
              }
            });

            const freeSpotsData = freeRes.data ?? freeRes;
            if (Array.isArray(freeSpotsData)) {
              freeCampsites = freeSpotsData.map((s: any) => ({
                _id: s._id,
                name: s.title,
                slug: s.slug,
                propertyType: 'free_spot',
                location: {
                  address: s.address,
                  city: s.city,
                  state: s.province || '',
                  coordinates: s.location?.coordinates ? {
                    lat: s.location.coordinates[1],
                    lng: s.location.coordinates[0]
                  } : undefined
                },
                pricing: { basePrice: 0 },
                images: s.images || [],
                rating: s.likeCount > 0 ? Number((4.5 + Math.min(0.5, s.likeCount * 0.1)).toFixed(1)) : 4.5,
                reviewCount: s.commentCount || 0,
                stats: { totalSites: 1 }
              }));
            }
          } catch (freeErr) {
            console.error(`Error searching free spots at stop ${d}:`, freeErr);
          }
        }

        // 3. Combine and limit results
        if (spotType === 'paid') {
          campsites = paidCampsites;
        } else if (spotType === 'free') {
          campsites = freeCampsites.slice(0, 3);
        } else {
          // 'all': Interleave results
          campsites = [];
          const maxLen = Math.max(paidCampsites.length, freeCampsites.length);
          for (let i = 0; i < maxLen; i++) {
            if (i < freeCampsites.length) campsites.push(freeCampsites[i]);
            if (i < paidCampsites.length) campsites.push(paidCampsites[i]);
          }
          campsites = campsites.slice(0, 3);
        }

        stops.push({
          dayNumber: d,
          fromName,
          toName,
          stopCoords,
          distanceKm,
          durationHrs,
          campsites,
          weather: weatherOptions[(d - 1) % weatherOptions.length],
          aiTip: aiTipsList[(d - 1) % aiTipsList.length]
        });
      }

      setItinerary(stops);
      toast.success('Đã lập lịch trình phượt thông minh thành công!');
    } catch (err) {
      console.error(err);
      toast.error('Có lỗi xảy ra khi tạo kế hoạch đường đi');
    } finally {
      setLoading(false);
    }
  };

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);
  };

  return (
    <div className="min-h-screen bg-slate-50/50 dark:bg-slate-950/20 text-slate-900 dark:text-slate-100 py-10">
      <div className="max-w-5xl mx-auto px-4 md:px-6">

        {/* Title Header */}
        <div className="text-center space-y-3 mb-10">
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-primary/10 text-primary text-xs font-bold uppercase tracking-wider animate-pulse">
            AI Roadtrip Planner
          </div>
          <h1 className="text-3xl md:text-4xl font-black tracking-tight text-slate-800 dark:text-white">
            Lập Lịch Trình Phượt Cắm Trại Thông Minh
          </h1>
          <p className="text-sm text-slate-500 max-w-xl mx-auto">
            Hệ thống tự động phân tích lộ trình của bạn, phân nhỏ chặng đường lái xe hợp lý và đề xuất những khu cắm trại tốt nhất của GoCamping dọc đường đi.
          </p>
        </div>

        {/* Search Panel Box */}
        <div className="bg-white dark:bg-slate-900 rounded-3xl border border-slate-200/80 dark:border-slate-850 p-6 shadow-xs mb-8">
          <form onSubmit={handlePlanRoute} className="grid grid-cols-1 md:grid-cols-12 gap-5 items-end">

            {/* Origin Input */}
            <div className="md:col-span-3 relative">
              <label className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block mb-1.5">Điểm xuất phát</label>
              <div className="relative">
                <MapPin className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  value={origin}
                  onChange={(e) => handleInputChange(e.target.value, 'origin')}
                  placeholder="Ví dụ: Hà Nội"
                  className="w-full pl-9 pr-4 py-2.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-primary/20 text-slate-800 dark:text-slate-100"
                  required
                />
              </div>

              {showOriginSuggestions && originSuggestions.length > 0 && (
                <div className="absolute left-0 right-0 mt-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-xl shadow-xl z-50 max-h-56 overflow-y-auto">
                  {originSuggestions.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => handleSelectSuggestion(s, 'origin')}
                      className="w-full text-left px-4 py-2.5 text-xs hover:bg-slate-100 dark:hover:bg-slate-800 border-b border-slate-100 dark:border-slate-850 last:border-0 truncate block text-slate-700 dark:text-slate-300"
                    >
                      {s.place_name}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Destination Input */}
            <div className="md:col-span-3 relative">
              <label className="text-[10px] font-bold text-slate-455 dark:text-slate-500 uppercase tracking-widest block mb-1.5">Điểm kết thúc</label>
              <div className="relative">
                <Navigation className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 rotate-45" />
                <input
                  type="text"
                  value={destination}
                  onChange={(e) => handleInputChange(e.target.value, 'dest')}
                  placeholder="Ví dụ: Hà Giang hoặc Đà Lạt"
                  className="w-full pl-9 pr-4 py-2.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-primary/20 text-slate-800 dark:text-slate-100"
                  required
                />
              </div>

              {showDestSuggestions && destSuggestions.length > 0 && (
                <div className="absolute left-0 right-0 mt-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-xl shadow-xl z-50 max-h-56 overflow-y-auto">
                  {destSuggestions.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => handleSelectSuggestion(s, 'dest')}
                      className="w-full text-left px-4 py-2.5 text-xs hover:bg-slate-100 dark:hover:bg-slate-800 border-b border-slate-100 dark:border-slate-850 last:border-0 truncate block text-slate-700 dark:text-slate-300"
                    >
                      {s.place_name}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Select days */}
            <div className="md:col-span-2">
              <label className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block mb-1.5">Số ngày đi</label>
              <select
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                className="w-full px-3 py-2.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-primary/20 cursor-pointer"
              >
                <option value={2}>2 ngày 1 đêm</option>
                <option value={3}>3 ngày 2 đêm</option>
                <option value={4}>4 ngày 3 đêm</option>
                <option value={5}>5 ngày 4 đêm</option>
              </select>
            </div>

            {/* Camping Style filter */}
            <div className="md:col-span-2">
              <label className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block mb-1.5">Loại hình lều</label>
              <select
                value={campingStyle}
                onChange={(e) => setCampingStyle(e.target.value)}
                className="w-full px-3 py-2.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-primary/20 cursor-pointer"
              >
                <option value="all">Tất cả lều</option>
                <option value="tent">Lều cắm trại (Tent)</option>
                <option value="glamping">Lều Glamping sang xịn</option>
                <option value="cabin">Nhà gỗ Cabin ấm cúng</option>
                <option value="rv">Khu cắm trại RV</option>
              </select>
            </div>

            {/* Spot Type filter */}
            <div className="md:col-span-2">
              <label className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block mb-1.5">Loại địa điểm</label>
              <select
                value={spotType}
                onChange={(e) => setSpotType(e.target.value)}
                className="w-full px-3 py-2.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-primary/20 cursor-pointer"
              >
                <option value="all">Tất cả điểm cắm</option>
                <option value="paid">GoCamping (Có phí)</option>
                <option value="free">Tự do (Miễn phí)</option>
              </select>
            </div>

            {/* Action Submit Button */}
            <div className="md:col-span-12 mt-2">
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-primary hover:bg-primary/90 text-white font-bold py-3 px-4 rounded-xl text-xs flex items-center justify-center gap-2 cursor-pointer shadow-md disabled:opacity-40 transition-all"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4.5 w-4.5 animate-spin" />
                    Đang thiết lập tuyến đường lái xe và quét campsite...
                  </>
                ) : (
                  <>
                    <Compass className="h-4.5 w-4.5" /> Lên lịch trình phượt thông minh
                  </>
                )}
              </button>
            </div>

          </form>
        </div>

        {/* Route info details */}
        {routeInfo && (
          <div className="flex items-center gap-6 p-4 rounded-2xl border border-primary/10 bg-primary/5 dark:bg-primary/10 border-slate-200/80 mb-8 animate-fade-in">
            <Car className="h-8 w-8 text-primary shrink-0 animate-bounce" />
            <div>
              <h3 className="text-sm font-black text-slate-850 dark:text-white">Chi tiết chặng hành trình phượt</h3>
              <p className="text-xs text-slate-500 mt-1 flex flex-wrap items-center gap-3">
                <span>Tổng khoảng cách: <strong className="text-slate-800 dark:text-slate-200">{routeInfo.totalDistance} km</strong></span>
                <span className="text-slate-300">•</span>
                <span>Thời gian lái xe ước tính: <strong className="text-slate-800 dark:text-slate-200">{routeInfo.totalDuration} giờ</strong></span>
                <span className="text-slate-300">•</span>
                <span>Số ngày du lịch: <strong className="text-slate-850 dark:text-slate-200">{days} ngày ({days - 1} đêm)</strong></span>
              </p>
            </div>
          </div>
        )}

        {/* Day-by-day Itinerary list */}
        {itinerary.length > 0 && (
          <div className="space-y-10 relative pl-4 md:pl-8 border-l-2 border-slate-200 dark:border-slate-800/85 animate-fade-in">
            {itinerary.map((stop, idx) => (
              <div key={stop.dayNumber} className="relative">

                {/* Timeline node */}
                <div className="absolute -left-[27px] md:-left-[43px] top-1 flex items-center justify-center h-8 w-8 rounded-full bg-primary border-4 border-white dark:border-slate-900 text-white font-black text-[10px] shadow-sm">
                  {stop.dayNumber}
                </div>

                <div className="space-y-4">

                  {/* Stop title */}
                  <div>
                    <h3 className="text-md font-black text-slate-850 dark:text-white flex items-center gap-2">
                      Ngày {stop.dayNumber}: {stop.fromName} <ArrowRight className="h-3.5 w-3.5 text-slate-400" /> {stop.toName}
                    </h3>
                    <div className="flex flex-wrap items-center gap-3 text-[10px] font-semibold text-slate-500 mt-1 block">
                      <span className="flex items-center gap-1"><Car className="h-3.5 w-3.5" /> Chặng lái xe: {stop.distanceKm} km (~{stop.durationHrs} giờ)</span>
                      <span>•</span>
                      <span>Thời tiết gợi ý: {stop.weather}</span>
                    </div>
                  </div>

                  {/* AI Tip block */}
                  <div className="p-3.5 rounded-2xl bg-primary/5 dark:bg-primary/10 border border-primary/20 flex items-start gap-3">
                    <Sparkles className="h-4.5 w-4.5 text-amber-500 shrink-0 mt-0.5" />
                    <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-350">{stop.aiTip}</p>
                  </div>

                  {/* Recommended Campsites at this chặng */}
                  <div className="space-y-3">
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5"><Tent className="h-4 w-4" /> Khu cắm trại đề xuất gần chặng dừng:</h4>
                    {stop.campsites.length === 0 ? (
                      <div className="p-5 rounded-2xl border border-dashed border-slate-200 dark:border-slate-800 text-center text-xs text-slate-400">
                        Chưa tìm thấy khu cắm trại nào phù hợp với bộ lọc trong bán kính 40km quanh chặng này.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                        {stop.campsites.map((camp) => (
                          <div key={camp._id} className="group bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/70 dark:border-slate-800/80 overflow-hidden hover:shadow-md transition-all duration-200 flex flex-col justify-between">

                            {/* Campsite cover image */}
                            <div className="relative h-28 bg-slate-100">
                              <img
                                src={camp.images?.[0] || '/placeholder.jpg'}
                                alt={camp.name}
                                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                              />
                              <div className="absolute top-2 left-2">
                                <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[9px] font-bold bg-primary text-white uppercase tracking-wider">
                                  {camp.propertyType === 'free_spot' ? 'Tự do' : camp.propertyType}
                                </span>
                              </div>
                            </div>

                            {/* Campsite body details */}
                            <div className="p-4 flex-1 flex flex-col justify-between space-y-3">
                              <div>
                                <h5 className="text-xs font-black text-slate-850 dark:text-white line-clamp-1 group-hover:text-primary transition-colors">{camp.name}</h5>
                                <p className="text-[10px] text-slate-400 mt-0.5 truncate">{camp.location?.city || camp.location?.address}, {camp.location?.state}</p>
                              </div>

                              <div className="flex items-center justify-between text-[10px]">
                                {camp.propertyType === 'free_spot' ? (
                                  <span className="font-bold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-2 py-0.5 rounded-md">Miễn phí</span>
                                ) : (
                                  <span className="font-bold text-emerald-600">{formatPrice(camp.pricing?.basePrice)}<span className="text-slate-400 font-normal">/đêm</span></span>
                                )}
                                <span className="inline-flex items-center gap-0.5 font-bold text-amber-500">
                                  <Star className="h-3.5 w-3.5 fill-current" /> {camp.rating}
                                </span>
                              </div>

                              <a
                                href={camp.propertyType === 'free_spot' ? `/free-spots/${camp._id}` : `/land/${camp.slug}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="w-full py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-primary/30 dark:hover:border-primary/50 text-[10px] font-bold hover:text-primary transition-all text-center flex items-center justify-center gap-1 block"
                              >
                                Xem Chi Tiết <ChevronRight className="h-3 w-3" />
                              </a>
                            </div>

                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                </div>
              </div>
            ))}
          </div>
        )}

      </div>
    </div>
  );
}
