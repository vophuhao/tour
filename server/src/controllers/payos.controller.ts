import catchErrors from "@/errors/catch-errors";
import PayOSService from "@/services/payos.service";

/**
 * Xử lý PayOS webhook
 * PayOS gửi chữ ký trong header x-payos-signature
 */
export const handlePayOSWebhook = catchErrors(async (req, res) => {
  const payOSService = new PayOSService();

  // Lấy signature từ header (PayOS gửi trong x-payos-signature)
  const signature = req.headers["x-payos-signature"] as string | undefined;

  const result = await payOSService.handlePayOS(req.body, signature);
  return res.status(200).json(result);
});
