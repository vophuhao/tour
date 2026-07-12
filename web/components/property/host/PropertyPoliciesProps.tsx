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

interface PropertyPoliciesProps {
  data: {
    depositRequired: boolean;
    depositAmount?: number;
    depositType?: "fixed" | "percentage";
    refundPolicy?: string;
    paymentMethods?: string[];
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
  const togglePaymentMethod = (method: string) => {
    const current = data.paymentMethods || [];
    const updated = current.includes(method)
      ? current.filter((m) => m !== method)
      : [...current, method];
    onChange({ paymentMethods: updated });
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Chính sách & Điều khoản
        </h3>
        <p className="text-sm text-gray-500 mb-6">
          Thiết lập chính sách hủy, thanh toán và hoàn tiền
        </p>
      </div>

      <div className="space-y-6">


        {/* Deposit Policy */}
        <Card>
          <CardHeader>
            <CardTitle>Chính sách đặt cọc</CardTitle>
            <CardDescription>
              Yêu cầu đặt cọc trước để giữ chỗ
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="depositRequired"
                checked={data.depositRequired}
                onCheckedChange={(checked) =>
                  onChange({ depositRequired: !!checked })
                }
              />
              <Label htmlFor="depositRequired" className="font-normal">
                Yêu cầu đặt cọc
              </Label>
            </div>

            {data.depositRequired && (
              <>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="depositType">Loại đặt cọc</Label>
                    <Select
                      value={data.depositType}
                      onValueChange={(value: any) =>
                        onChange({ depositType: value })
                      }
                    >
                      <SelectTrigger className="mt-1">
                        <SelectValue placeholder="Chọn loại" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="fixed">Số tiền cố định</SelectItem>
                        <SelectItem value="percentage">Phần trăm</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="depositAmount">
                      {data.depositType === "percentage"
                        ? "Phần trăm (%)"
                        : "Số tiền (VNĐ)"}
                    </Label>
                    <Input
                      id="depositAmount"
                      type="number"
                      value={data.depositAmount || ""}
                      onChange={(e) =>
                        onChange({ depositAmount: parseFloat(e.target.value) })
                      }
                      min="0"
                      max={data.depositType === "percentage" ? 100 : undefined}
                      className="mt-1"
                    />
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Refund Policy */}
        <Card>
          <CardHeader>
            <CardTitle>Chính sách hoàn tiền</CardTitle>
            <CardDescription>
              Mô tả cách thức hoàn tiền cho khách
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              value={data.refundPolicy}
              onChange={(e) => onChange({ refundPolicy: e.target.value })}
              placeholder="VD: Tiền cọc sẽ được hoàn lại trong vòng 7 ngày làm việc sau khi check-out..."
              rows={5}
              maxLength={1000}
            />
            <p className="text-xs text-gray-500 mt-1">
              {data.refundPolicy?.length || 0}/1000 ký tự
            </p>
          </CardContent>
        </Card>

        {/* Payment Methods */}
        <Card>
          <CardHeader>
            <CardTitle>Phương thức thanh toán</CardTitle>
            <CardDescription>
              Chọn các phương thức thanh toán bạn chấp nhận
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {PAYMENT_METHODS.map((method) => (
                <div key={method.value} className="flex items-center space-x-2">
                  <Checkbox
                    id={method.value}
                    checked={data.paymentMethods?.includes(method.value)}
                    onCheckedChange={() => togglePaymentMethod(method.value)}
                  />
                  <Label htmlFor={method.value} className="font-normal">
                    {method.label}
                  </Label>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}