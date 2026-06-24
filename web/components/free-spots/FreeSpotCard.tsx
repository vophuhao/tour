'use client';

import Image from 'next/image';
import { Heart, Eye, MapPin, User } from 'lucide-react';
import Link from 'next/link';
import type { FreeSpot } from '@/lib/free-spot-api';
import TerrainBadge from './TerrainBadge';

interface Props {
  spot: FreeSpot;
  highlighted?: boolean;
  onHover?: (id: string | null) => void;
}

export default function FreeSpotCard({ spot, highlighted, onHover }: Props) {
  const thumb = spot.images?.[0];
  const lat = spot.location?.coordinates?.[1];
  const lng = spot.location?.coordinates?.[0];

  return (
    <Link
      href={`/free-spots/${spot._id}`}
      className={`group flex flex-col overflow-hidden rounded-2xl border bg-card transition-all duration-300 cursor-pointer text-current no-underline focus-visible:ring-4 focus-visible:ring-primary/20 outline-hidden ${highlighted
        ? 'border-primary ring-4 ring-primary/10 shadow-md scale-101'
        : 'border-border shadow-xs hover:shadow-md hover:-translate-y-0.5'
        }`}
      onMouseEnter={() => onHover?.(spot._id)}
      onMouseLeave={() => onHover?.(null)}
    >
      {/* Thumbnail */}
      <div className="relative h-44 w-full bg-muted flex-shrink-0 overflow-hidden">
        {thumb ? (
          <Image
            src={thumb}
            alt={spot.title}
            fill
            sizes="(max-width: 768px) 100vw, 400px"
            className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            unoptimized
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center text-4xl text-muted-foreground select-none">
            🏕️
          </div>
        )}

      </div>

      {/* Content */}
      <div className="p-4 flex-1 flex flex-col gap-3">
        <h3 className="font-bold text-sm text-foreground leading-snug line-clamp-2 group-hover:text-primary transition-colors">
          {spot.title}
        </h3>

        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <MapPin size={13} className="shrink-0 text-primary/70" />
          <span className="truncate">
            {spot.address}, {spot.city}
          </span>
        </div>

        <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 flex-1">
          {spot.description}
        </p>

        {/* Footer */}
        <div className="pt-3 border-t border-border flex items-center justify-between text-xs mt-1">
          {/* Author */}
          <div className="flex items-center gap-2">
            {spot.author?.avatarUrl ? (
              <div className="relative w-5.5 h-5.5 rounded-full overflow-hidden border border-border shrink-0">
                <Image
                  src={spot.author.avatarUrl}
                  alt={spot.author.username}
                  fill
                  className="object-cover"
                  unoptimized
                />
              </div>
            ) : (
              <div className="w-5.5 h-5.5 rounded-full bg-primary/10 flex items-center justify-center text-primary font-bold">
                {spot.author?.username?.charAt(0).toUpperCase() || 'U'}
              </div>
            )}
            <span className="text-muted-foreground font-semibold truncate max-w-[100px]">
              {spot.author?.username}
            </span>
          </div>

          {/* Stats */}
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1 text-rose-500 font-semibold">
              <Heart size={13} fill="#ef4444" />
              <span>{spot.likeCount ?? 0}</span>
            </span>
            <span className="flex items-center gap-1 text-muted-foreground font-semibold">
              <Eye size={13} />
              <span>{spot.viewCount ?? 0}</span>
            </span>
          </div>
        </div>
      </div>
    </Link>
  );
}
