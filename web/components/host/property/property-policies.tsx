/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface RefundRule {
  daysBeforeCheckIn: number;
  refundPercentage: number;
}

interface PropertyRule {
  text: string;
  category: "pets" | "noise" | "fire" | "general";
  order: number;
}

interface PropertyPoliciesProps {
  data: {
    depositRequired?: boolean;
    depositAmount?: number;
    depositType?: "fixed" | "percentage";
    refundPolicy?: string;
    paymentMethods?: string[];
    rules?: PropertyRule[];
  };
  onChange: (data: any) => void;
}

const PAYMENT_METHODS = [
  { value: "cash", label: "Tiền mặt" },
  { value: "bank_transfer", label: "Chuyển khoản" },
  { value: "credit_card", label: "Thẻ tín dụng" },
  { value: "momo", label: "MoMo" },
  { value: "zalopay", label: "ZaloPay" },
];

export function PropertyPolicies({ data, onChange }: PropertyPoliciesProps) {
  // Helpers for rules
  const rulesList = data.rules ?? [];

  const addRule = () => {
    const list = [...rulesList, { text: "", category: "general", order: rulesList.length }];
    onChange({ rules: list });
  };

  const updateRule = (idx: number, patch: Partial<PropertyRule>) => {
    const list = rulesList.map((r, i) => (i === idx ? { ...r, ...patch } : r));
    onChange({ rules: list });
  };

  const removeRule = (idx: number) => {
    const list = rulesList.filter((_, i) => i !== idx).map((r, i) => ({ ...r, order: i }));
    onChange({ rules: list });
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-2">Quy định của Property</h3>
        <p className="text-sm text-gray-500">Thiết lập các nội quy và quy định khi khách lưu trú tại property của bạn.</p>
      </div>

      <div className="space-y-6">
        {/* Property Rules */}
        <Card>
          <CardHeader>
            <CardTitle>Quy định lưu trú</CardTitle>
            <CardDescription>Danh sách các quy định (ví dụ: không đưa thú cưng, giữ trật tự, lửa trại...)</CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label>Quy định</Label>
              <Button size="sm" onClick={addRule}>Thêm quy định</Button>
            </div>

            <div className="space-y-2">
              {rulesList.length === 0 && <p className="text-xs text-gray-500">Chưa có quy định nào</p>}

              {rulesList.map((r, idx) => (
                <div key={idx} className="flex gap-2 items-start bg-white border rounded-md p-3">
                  <div className="flex-1 space-y-2">
                    <div>
                      <Label className="text-xs">Nội dung</Label>
                      <Input
                        value={r.text}
                        onChange={(e) => updateRule(idx, { text: e.target.value })}
                        className="mt-1"
                      />
                    </div>

                    <div className="flex gap-2 items-center">
                      <div className="w-36">
                        <Label className="text-xs">Loại</Label>
                        <Select
                          value={r.category}
                          onValueChange={(v: any) => updateRule(idx, { category: v })}
                        >
                          <SelectTrigger className="mt-1">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="general">Chung</SelectItem>
                            <SelectItem value="pets">Thú cưng</SelectItem>
                            <SelectItem value="noise">Tiếng ồn</SelectItem>
                            <SelectItem value="fire">Lửa trại</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="w-28">
                        <Label className="text-xs">Thứ tự</Label>
                        <Input
                          type="number"
                          value={r.order}
                          onChange={(e) => updateRule(idx, { order: parseInt(e.target.value || "0") })}
                          className="mt-1"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center">
                    <Button size="sm" variant="ghost" onClick={() => removeRule(idx)}>Xóa</Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}