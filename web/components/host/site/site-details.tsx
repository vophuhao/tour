/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { SiteBasicInfo } from "./site-basic-info";
import { SiteAccommodationType } from "./site-accommodation-type";
import { SiteCapacity } from "./site-capacity";
import { SitePricing } from "./site-pricing";

interface SiteDetailsProps {
  data: {
    basic?: any;
    accommodationType?: any;
    lodgingProvided?: any;
    terrain?: any;
    capacity?: any;
    pricing?: any;
    unitNames?: string[];
  } | undefined;
  onChange: (patch: Partial<{ basic: any; accommodationType: any; lodgingProvided: any; terrain: any; capacity: any; pricing: any; unitNames: string[] }>) => void;
}

export function SiteDetails({ data = {}, onChange }: SiteDetailsProps) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-1 gap-6">
        <SiteBasicInfo
          data={data.basic ?? {}}
          onChange={(d: any) => onChange({ basic: { ...(data.basic ?? {}), ...(d ?? {}) } })}
        />

        <div className="space-y-6">
          <SiteAccommodationType
            data={{
              type: typeof data.accommodationType === "string" ? data.accommodationType : data.accommodationType?.type ?? "",
              lodgingProvided: data.lodgingProvided ?? undefined,
              terrain: data.terrain ?? undefined,
            }}
            onChange={(patch) => onChange(patch)}
          />

          <SiteCapacity
            data={data.capacity}
            accommodationType={typeof data.accommodationType === "string" ? data.accommodationType : data.accommodationType?.type}
            lodgingProvided={data.lodgingProvided}
            unitNames={data.unitNames}
            onChange={(newCapacity) => onChange({ capacity: newCapacity })}
            onUnitNamesChange={(newUnitNames) => onChange({ unitNames: newUnitNames })}
          />

          <SitePricing
            data={data.pricing ?? {}}
            onChange={(newPricing) => onChange({ pricing: newPricing })}
          />
        </div>
      </div>
    </div>
  );
}