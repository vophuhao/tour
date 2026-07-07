import { catchErrors, ErrorFactory } from "@/errors";
import { BookingModel, ReviewModel, PropertyModel } from "@/models";
import HostModel from "@/models/host.model";
import { ResponseUtil, sendMail } from "../utils";
import UserModel from "../models/user.model";
import appAssert from "../utils/app-assert";
import { NotificationService } from "@/services";
import axios from "axios";

export default class UserController {
  getUserHandler = catchErrors(async (req, res) => {
    const user = await UserModel.findById(req.userId);
    appAssert(user, ErrorFactory.resourceNotFound("User"));
    return ResponseUtil.success(res, user, "Lấy thông tin user thành công");
  });

  getAllHost = catchErrors(async (_req, res) => {
    const hosts = await UserModel.find({ role: "host" }).select(
      "username email avatarUrl createdAt isBlocked phoneNumber bio"
    );

    const hostsWithStats = await Promise.all(
      hosts.map(async (host) => {
        // locationCount (number of properties owned by host)
        const locationCount = await PropertyModel.countDocuments({ host: host._id });

        // totalBookings
        const totalBookings = await BookingModel.countDocuments({ host: host._id });

        // totalRevenue (sum of pricing.total for paid or completed bookings)
        const bookings = await BookingModel.find({
          host: host._id,
          status: { $in: ["confirmed", "completed"] },
          paymentStatus: "paid",
        }).select("pricing.total");
        const totalRevenue = bookings.reduce((sum, b) => sum + (b.pricing?.total || 0), 0);

        // rating (average rating of properties)
        const properties = await PropertyModel.find({ host: host._id }).select("stats.averageRating");
        const rating = properties.length > 0
          ? properties.reduce((sum, p) => sum + (p.stats?.averageRating || 0), 0) / properties.length
          : 0;

        // KYC host info
        const hostKyc = await HostModel.findOne({ user: host._id });

        return {
          ...host.toObject(),
          phone: host.phoneNumber || hostKyc?.phone || "",
          address: hostKyc?.bankInfo?.bankName ? `${hostKyc.bankInfo.bankName} - ${hostKyc.bankInfo.accountNumber}` : "",
          locationCount,
          totalBookings,
          totalRevenue,
          rating,
          verifiedAt: hostKyc?.createdAt || host.createdAt,
          isActive: !host.isBlocked,
        };
      })
    );

    return ResponseUtil.success(res, hostsWithStats, "Lấy danh sách host thành công");
  });

  getUserByUsernameHandler = catchErrors(async (req, res) => {
    const { username } = req.params;
    const user = await UserModel.findOne({ username });
    appAssert(user, ErrorFactory.resourceNotFound("User"));
    return ResponseUtil.success(res, user, "Lấy thông tin user thành công");
  });

  updateProfileHandler = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidToken("Authentication required"));

    const { username, bio, avatar } = req.body;

    // Build update object
    const updateData: Record<string, string> = {};
    if (username) updateData.username = username;
    if (bio !== undefined) updateData.bio = bio;
    if (avatar) updateData.avatarUrl = avatar;

    // Check if username is already taken (if changing)
    if (username) {
      const existingUser = await UserModel.findOne({
        username,
        _id: { $ne: userId },
      });
      appAssert(!existingUser, ErrorFactory.resourceExists("Username"));
    }

    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true }
    );
    appAssert(updatedUser, ErrorFactory.resourceNotFound("User"));

    return ResponseUtil.success(res, updatedUser.omitPassword(), "Cập nhật thông tin thành công");
  });

  searchUsers = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { q } = req.query;
    appAssert(q, ErrorFactory.badRequest("Thiếu từ khóa tìm kiếm"));

    const query = String(q).trim();

    // Tìm kiếm theo username, full_name, email
    const users = await UserModel.find({
      _id: { $ne: userId },
      role: "host",
      $or: [
        { username: { $regex: query, $options: "i" } },
        { email: { $regex: query, $options: "i" } },
        { role: "host" },
      ],
    })
      .select("username avatarUrl email")
      .limit(10);

    return ResponseUtil.success(res, users, "Search results");
  });

  getAllUsers = catchErrors(async (_req, res) => {
    const users = await UserModel.find().select("username email role createdAt avatarUrl isBlocked");
    return ResponseUtil.success(res, users, "Lấy danh sách người dùng thành công");
  });

  becomeHostHandler = catchErrors(async (req, res) => {
    const userId = req.userId;

    const data = req.body;
    data.user = userId;
    await HostModel.create(data);

    // Send notification to all admins
    try {
      const { container, TOKENS } = await import("@/di");
      // const NotificationService = (await import("@/services/notification.service")).default;
      const notificationService = container.resolve<NotificationService>(TOKENS.NotificationService);
      const user = await UserModel.findById(userId);
      const admins = await UserModel.find({ role: "admin" });

      for (const admin of admins) {
        await notificationService.createNewHostRequestForAdmin(
          admin._id!.toString(),
          userId!.toString(),
          user?.username || "User",
          user?.email || data.gmail
        );
      }
    } catch (error) {
      console.error("Failed to send host request notification to admin:", error);
    }

    return ResponseUtil.success(res, null, "Đăng ký trở thành host thành công");
  });

  getAllBecomeHost = catchErrors(async (_req, res) => {
    const hosts = await HostModel.find().populate("user", "username email avatarUrl");
    return ResponseUtil.success(res, hosts, "Lấy danh sách đăng ký host thành công");
  });

  updateStatusHostHandler = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    const host = await HostModel.findById(id);
    const user = await UserModel.findById(host?.user);
    appAssert(host, ErrorFactory.resourceNotFound("Host request"));

    const previousStatus = host.status;
    host.status = status;
    await host.save();

    // Gửi email thông báo
    if (status === "approved" && previousStatus !== "approved") {
      await sendMail({
        to: host.gmail,
        subject: "🎉 Chúc mừng! Yêu cầu trở thành Host đã được chấp nhận",
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
              .content { background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }
              .button { display: inline-block; background: #10b981; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
              .info-box { background: white; padding: 20px; border-left: 4px solid #10b981; margin: 20px 0; border-radius: 5px; }
              .footer { text-align: center; color: #6b7280; font-size: 12px; margin-top: 30px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>🎉 Chúc mừng ${host.name}!</h1>
                <p style="font-size: 18px; margin: 10px 0;">Bạn đã trở thành Host chính thức</p>
              </div>
              
              <div class="content">
                <p>Xin chào <strong>${host.name}</strong>,</p>
                
                <p>Chúc mừng! Yêu cầu trở thành Host của bạn đã được <strong style="color: #10b981;">CHẤP NHẬN</strong>.</p>
                
                <div class="info-box">
                  <h3 style="margin-top: 0; color: #10b981;">📋 Thông tin tài khoản Host</h3>
                  <p><strong>Tên:</strong> ${host.name}</p>
                  <p><strong>Email:</strong> ${host.gmail}</p>
                  ${host.phone ? `<p><strong>Số điện thoại:</strong> ${host.phone}</p>` : ""}
                  <p><strong>Trạng thái:</strong> <span style="color: #10b981; font-weight: bold;">Đã kích hoạt</span></p>
                </div>
                
                <h3>🚀 Bước tiếp theo:</h3>
                <ul>
                  <li>Đăng nhập vào hệ thống với tài khoản của bạn</li>
                  <li>Tạo địa điểm cắm trại đầu tiên của bạn</li>
                  <li>Thiết lập giá cả và quy định</li>
                  <li>Bắt đầu đón khách và kinh doanh</li>
                </ul>
                
                <div style="text-align: center;">
                  <a href="${process.env.CLIENT_URL}/host/locations/create" class="button">
                    Tạo địa điểm ngay
                  </a>
                </div>
                
                <p style="margin-top: 30px;">Chúng tôi rất vui mừng được đồng hành cùng bạn trên con đường phát triển kinh doanh du lịch cắm trại!</p>
                
                <p>Nếu có bất kỳ câu hỏi nào, đừng ngần ngại liên hệ với chúng tôi.</p>
                
                <p style="margin-top: 20px;">
                  Trân trọng,<br>
                  <strong>Đội ngũ HipCamp</strong>
                </p>
              </div>
              
              <div class="footer">
                <p>© ${new Date().getFullYear()} HipCamp. All rights reserved.</p>
                <p>Email này được gửi tự động, vui lòng không phản hồi.</p>
              </div>
            </div>
          </body>
          </html>
        `,
      });
      await user?.updateOne({ role: "host" });
    } else if (status === "rejected" && previousStatus !== "rejected") {
      // Email cho rejected
      await sendMail({
        to: host.gmail,
        subject: "❌ Thông báo về yêu cầu trở thành Host",
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
              .content { background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }
              .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
              .info-box { background: white; padding: 20px; border-left: 4px solid #ef4444; margin: 20px 0; border-radius: 5px; }
              .tips-box { background: #dbeafe; padding: 20px; border-left: 4px solid #3b82f6; margin: 20px 0; border-radius: 5px; }
              .footer { text-align: center; color: #6b7280; font-size: 12px; margin-top: 30px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Thông báo về yêu cầu Host</h1>
                <p style="font-size: 16px; margin: 10px 0;">Yêu cầu của bạn chưa được chấp nhận</p>
              </div>
              
              <div class="content">
                <p>Xin chào <strong>${host.name}</strong>,</p>
                
                <p>Cảm ơn bạn đã quan tâm và gửi yêu cầu trở thành Host trên nền tảng của chúng tôi.</p>
                
                <div class="info-box">
                  <h3 style="margin-top: 0; color: #ef4444;">📋 Thông tin yêu cầu</h3>
                  <p><strong>Tên:</strong> ${host.name}</p>
                  <p><strong>Email:</strong> ${host.gmail}</p>
                  ${host.phone ? `<p><strong>Số điện thoại:</strong> ${host.phone}</p>` : ""}
                  <p><strong>Trạng thái:</strong> <span style="color: #ef4444; font-weight: bold;">Chưa được chấp nhận</span></p>
                </div>
                
                <p>Rất tiếc, yêu cầu của bạn <strong>chưa được chấp nhận</strong> vào lúc này. Điều này có thể do một trong những lý do sau:</p>
                
                <div class="tips-box">
                  <h3 style="margin-top: 0; color: #3b82f6;">💡 Các lý do thường gặp:</h3>
                  <ul>
                    <li>Thông tin cung cấp chưa đầy đủ hoặc chưa chính xác</li>
                    <li>Chưa đáp ứng các tiêu chuẩn về chất lượng dịch vụ</li>
                    <li>Địa điểm dự kiến chưa phù hợp với quy định</li>
                    <li>Cần bổ sung thêm giấy tờ hoặc chứng nhận</li>
                  </ul>
                </div>
                
                <h3>🔄 Bạn có thể làm gì tiếp theo?</h3>
                <ul>
                  <li>Kiểm tra và cập nhật đầy đủ thông tin cá nhân</li>
                  <li>Chuẩn bị các giấy tờ cần thiết (nếu có)</li>
                  <li>Liên hệ với chúng tôi để được tư vấn chi tiết</li>
                  <li>Gửi lại yêu cầu sau khi đã hoàn thiện hồ sơ</li>
                </ul>
                
                <div style="text-align: center;">
                  <a href="${process.env.CLIENT_URL}/contact" class="button">
                    Liên hệ hỗ trợ
                  </a>
                </div>
                
                <p style="margin-top: 30px;">Chúng tôi rất mong được hợp tác với bạn trong tương lai. Đừng nản lòng và hãy thử lại sau khi đã hoàn thiện hồ sơ nhé!</p>
                
                <p style="margin-top: 20px;">
                  Trân trọng,<br>
                  <strong>Đội ngũ HipCamp</strong>
                </p>
              </div>
              
              <div class="footer">
                <p>© ${new Date().getFullYear()} HipCamp. All rights reserved.</p>
                <p>Nếu có thắc mắc, vui lòng liên hệ: support@hipcamp.vn</p>
              </div>
            </div>
          </body>
          </html>
        `,
      });
    }

    return ResponseUtil.success(res, null, "Cập nhật trạng thái host thành công");
  });

  /**
   * Get user stats (bookings, orders, reviews count)
   * @route GET /api/users/:username/stats
   */
  getUserStats = catchErrors(async (req, res) => {
    const { username } = req.params;
    const user = await UserModel.findOne({ username });
    appAssert(user, ErrorFactory.resourceNotFound("User"));

    // Count bookings where user is guest
    const bookingsCount = await BookingModel.countDocuments({ guest: user._id });


    // Count reviews written by user
    const reviewsCount = await ReviewModel.countDocuments({ guest: user._id, isPublished: true });


    return ResponseUtil.success(
      res,
      {
        bookings: bookingsCount,

        reviews: reviewsCount,

      },
      "Lấy thống kê user thành công"
    );
  });

  /**
   * Get user reviews
   * @route GET /api/users/:username/reviews
   */
  getUserReviews = catchErrors(async (req, res) => {
    const { username } = req.params;
    const user = await UserModel.findOne({ username });
    appAssert(user, ErrorFactory.resourceNotFound("User"));

    const reviews = await ReviewModel.find({ guest: user._id, isPublished: true })
      .populate("property", "name slug photos location")
      .populate("site", "name")
      .populate("booking", "checkIn checkOut")
      .sort({ createdAt: -1 })
      .lean();

    return ResponseUtil.success(res, reviews, "Lấy danh sách review thành công");
  });

  blockUser = catchErrors(async (req, res) => {
    const { id } = req.params;
    const user = await UserModel.findById(id);
    appAssert(user, ErrorFactory.resourceNotFound("User"));
    user.isBlocked = !user.isBlocked;
    await user.save();
    return ResponseUtil.success(res, null, "Khóa người dùng thành công");
  });

  validateCccdHandler = catchErrors(async (req, res) => {
    const { idNumber, idCardImage } = req.body;

    appAssert(idNumber, ErrorFactory.badRequest("Thiếu số CCCD"));
    appAssert(idCardImage, ErrorFactory.badRequest("Thiếu ảnh mặt trước CCCD"));

    const cccdRegex = /^\d{12}$/;
    appAssert(cccdRegex.test(idNumber.replace(/\s/g, "")), ErrorFactory.badRequest("Số CCCD không hợp lệ (cần 12 chữ số)"));

    const apiKey = process.env.GOOGLE_GENERATIVE_AI_API_KEY;
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    try {
      const prompt = `Bạn là một trợ lý OCR và xác thực giấy tờ tùy thân.
Hãy phân tích hình ảnh mặt trước của thẻ căn cước được cung cấp và xác định xem đó có phải là ảnh chụp mặt trước của Căn cước công dân (CCCD) hoặc Thẻ Căn cước của Việt Nam hay không.

Trả về DUY NHẤT một chuỗi JSON hợp lệ (không bọc trong block code \`\`\`json, không chứa bất kỳ lời giải thích nào khác ngoài JSON) có định dạng như sau:
{
  "isVNIDCard": boolean, // true nếu là mặt trước của CCCD/Thẻ Căn cước Việt Nam hợp lệ, false nếu không phải (ví dụ: ảnh phong cảnh, ảnh người thông thường, bằng lái xe, hoặc CMND cũ/nước ngoài...)
  "idNumber": "string | null", // Số CCCD gồm 12 chữ số được trích xuất từ ảnh. Ghi null nếu không tìm thấy.
  "fullName": "string | null", // Họ và tên đầy đủ viết hoa (ví dụ: "NGUYỄN VĂN A") trích xuất từ ảnh. Ghi null nếu không tìm thấy.
  "reason": "string" // Lý do nếu không phải CCCD Việt Nam, hoặc mô tả kết quả nếu đúng.
}`;

      const geminiResponse = await axios.post(geminiUrl, {
        contents: [{
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType: "image/jpeg",
                data: idCardImage
              }
            }
          ]
        }]
      });

      const generatedText = geminiResponse.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      let cleanedText = generatedText.trim();
      if (cleanedText.startsWith("```json")) {
        cleanedText = cleanedText.slice(7);
      } else if (cleanedText.startsWith("```")) {
        cleanedText = cleanedText.slice(3);
      }
      if (cleanedText.endsWith("```")) {
        cleanedText = cleanedText.slice(0, -3);
      }
      cleanedText = cleanedText.trim();

      const result = JSON.parse(cleanedText);

      appAssert(
        result.isVNIDCard,
        ErrorFactory.badRequest(result.reason || "Ảnh tải lên không phải là ảnh mặt trước Căn cước công dân (CCCD) Việt Nam hợp lệ. Vui lòng chụp rõ nét mặt trước CCCD.")
      );

      if (result.idNumber) {
        const userCccd = idNumber.replace(/\s/g, "");
        const ocrCccd = result.idNumber.replace(/\s/g, "");
        appAssert(
          userCccd === ocrCccd,
          ErrorFactory.badRequest(`Số CCCD trích xuất từ ảnh (${result.idNumber}) không khớp với số CCCD bạn đã nhập (${idNumber}).`)
        );
      }

      return ResponseUtil.success(res, result, "CCCD Việt Nam hợp lệ");
    } catch (err: any) {
      console.error("Lỗi xác thực CCCD bằng Gemini:", err);
      if (err.statusCode) {
        throw err;
      }
      throw ErrorFactory.badRequest(err.message || "Không thể xác thực ảnh CCCD. Vui lòng chụp rõ nét, đủ ánh sáng và thử lại.");
    }
  });

  /**
   * KYC-based host registration
   * Validates age from CCCD number and upgrades role automatically
   * @route POST /users/kyc-become-host
   */
  kycBecomeHostHandler = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidToken("Yêu cầu đăng nhập"));

    const { name, gmail, phone, idNumber, faceMatchScore, selfieImage, idCardImage } = req.body;

    // Validate required fields
    appAssert(name, ErrorFactory.badRequest("Thiếu họ tên"));
    appAssert(gmail, ErrorFactory.badRequest("Thiếu email"));
    appAssert(idNumber, ErrorFactory.badRequest("Thiếu số CCCD"));
    appAssert(selfieImage, ErrorFactory.badRequest("Thiếu ảnh selfie"));
    appAssert(idCardImage, ErrorFactory.badRequest("Thiếu ảnh mặt trước CCCD"));

    // Validate CCCD format (12 digits)
    const cccdRegex = /^\d{12}$/;
    appAssert(cccdRegex.test(idNumber.replace(/\s/g, "")), ErrorFactory.badRequest("Số CCCD không hợp lệ (cần 12 chữ số)"));

    // Validate CCCD front image using Gemini OCR/Verification
    const apiKey = process.env.GOOGLE_GENERATIVE_AI_API_KEY;
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    try {
      const prompt = `Bạn là một trợ lý OCR và xác thực giấy tờ tùy thân.
Hãy phân tích hình ảnh mặt trước của thẻ căn cước được cung cấp và xác định xem đó có phải là ảnh chụp mặt trước của Căn cước công dân (CCCD) hoặc Thẻ Căn cước của Việt Nam hay không.

Trả về DUY NHẤT một chuỗi JSON hợp lệ (không bọc trong block code \`\`\`json, không chứa bất kỳ lời giải thích nào khác ngoài JSON) có định dạng như sau:
{
  "isVNIDCard": boolean, // true nếu là mặt trước của CCCD/Thẻ Căn cước Việt Nam hợp lệ, false nếu không phải (ví dụ: ảnh phong cảnh, ảnh người thông thường, bằng lái xe, hoặc CMND cũ/nước ngoài...)
  "idNumber": "string | null", // Số CCCD gồm 12 chữ số được trích xuất từ ảnh. Ghi null nếu không tìm thấy.
  "fullName": "string | null", // Họ và tên đầy đủ viết hoa (ví dụ: "NGUYỄN VĂN A") trích xuất từ ảnh. Ghi null nếu không tìm thấy.
  "reason": "string" // Lý do nếu không phải CCCD Việt Nam, hoặc mô tả kết quả nếu đúng.
}`;

      const geminiResponse = await axios.post(geminiUrl, {
        contents: [{
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType: "image/jpeg",
                data: idCardImage
              }
            }
          ]
        }]
      });

      const generatedText = geminiResponse.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      let cleanedText = generatedText.trim();
      if (cleanedText.startsWith("```json")) {
        cleanedText = cleanedText.slice(7);
      } else if (cleanedText.startsWith("```")) {
        cleanedText = cleanedText.slice(3);
      }
      if (cleanedText.endsWith("```")) {
        cleanedText = cleanedText.slice(0, -3);
      }
      cleanedText = cleanedText.trim();

      const result = JSON.parse(cleanedText);

      appAssert(
        result.isVNIDCard,
        ErrorFactory.badRequest(result.reason || "Ảnh tải lên không phải là ảnh mặt trước Căn cước công dân (CCCD) Việt Nam hợp lệ. Vui lòng chụp rõ nét mặt trước CCCD.")
      );

      // Verify that the ID number matches the user-inputted ID number
      if (result.idNumber) {
        const userCccd = idNumber.replace(/\s/g, "");
        const ocrCccd = result.idNumber.replace(/\s/g, "");
        appAssert(
          userCccd === ocrCccd,
          ErrorFactory.badRequest(`Số CCCD trích xuất từ ảnh (${result.idNumber}) không khớp với số CCCD bạn đã nhập (${idNumber}).`)
        );
      }
    } catch (err: any) {
      console.error("Lỗi xác thực CCCD bằng Gemini:", err);
      if (err.statusCode) {
        throw err;
      }
      throw ErrorFactory.badRequest("Không thể xác thực ảnh CCCD. Vui lòng chụp rõ nét, đủ ánh sáng và thử lại.");
    }

    const cccd = idNumber.replace(/\s/g, "");

    // Parse birth year from CCCD 12 digits
    // Format: [3-digit province][1-digit gender+decade][2-digit year][6-digit sequence]
    // Digit 4 (index 3): 0=male 190x, 1=male 199x, 2=male 200x, 3=female 190x, 4=female 199x, 5=female 200x, 6=male 201x, 7=female 201x, 8=male 201x+, 9=female 201x+
    const decadeCode = parseInt(cccd[3], 10);
    const yearSuffix = cccd.slice(4, 6); // 2 digits

    let birthYear: number;
    if (decadeCode === 0) birthYear = 1900 + parseInt(yearSuffix, 10);
    else if (decadeCode === 1) birthYear = 1900 + parseInt(yearSuffix, 10); // 199x
    else if (decadeCode === 2) birthYear = 2000 + parseInt(yearSuffix, 10);
    else if (decadeCode === 3) birthYear = 1900 + parseInt(yearSuffix, 10);
    else if (decadeCode === 4) birthYear = 1900 + parseInt(yearSuffix, 10); // 199x female
    else if (decadeCode === 5) birthYear = 2000 + parseInt(yearSuffix, 10);
    else if (decadeCode === 6) birthYear = 2010 + parseInt(yearSuffix, 10);
    else if (decadeCode === 7) birthYear = 2010 + parseInt(yearSuffix, 10);
    else birthYear = 2000 + parseInt(yearSuffix, 10);

    // Refine: decade 0 = 190x, 1 = 199x (not 190x)
    // Vietnamese CCCD: digit[3] encodes gender+decade-of-birth
    // 0: male, 1900-1909... but realistically:
    // We trust the 2-digit year suffix directly with the decade hint
    if (decadeCode <= 2) {
      // Male
      if (decadeCode === 0) birthYear = 1900 + parseInt(yearSuffix, 10);
      else if (decadeCode === 1) birthYear = 1900 + parseInt(yearSuffix, 10);
      else birthYear = 2000 + parseInt(yearSuffix, 10);
    } else if (decadeCode <= 5) {
      // Female
      if (decadeCode === 3) birthYear = 1900 + parseInt(yearSuffix, 10);
      else if (decadeCode === 4) birthYear = 1900 + parseInt(yearSuffix, 10);
      else birthYear = 2000 + parseInt(yearSuffix, 10);
    } else {
      birthYear = 2000 + parseInt(yearSuffix, 10);
    }

    const currentYear = new Date().getFullYear();
    const age = currentYear - birthYear;

    appAssert(age >= 18, ErrorFactory.badRequest(`Bạn chưa đủ 18 tuổi. Năm sinh được xác định: ${birthYear}`));

    // Validate face match score (sent from client-side face-api comparison)
    const matchScore = parseFloat(faceMatchScore ?? "0");
    appAssert(
      matchScore >= 0.5,
      ErrorFactory.badRequest("Khuôn mặt không khớp với ảnh CCCD. Vui lòng thử lại với ánh sáng tốt hơn.")
    );

    // Check if user already is a host
    const user = await UserModel.findById(userId);
    appAssert(user, ErrorFactory.resourceNotFound("User"));
    appAssert(user.role !== "host", ErrorFactory.badRequest("Tài khoản đã có quyền Host"));

    // Upgrade role to host
    await UserModel.findByIdAndUpdate(userId, {
      $set: {
        role: "host",
        phoneNumber: phone || user.phoneNumber,
      },
    });

    // Also create HostModel record for tracking
    try {
      await HostModel.create({
        user: userId,
        name,
        gmail,
        phone,
        idNumber: cccd,
        status: "approved",
        verifiedAt: new Date(),
        birthYear,
      });
    } catch (e) {
      // Non-critical – role already upgraded
      console.warn("Could not create HostModel record:", e);
    }

    return ResponseUtil.success(res, { birthYear, age }, "Xác minh thành công! Tài khoản của bạn đã được nâng cấp thành Host.");
  });
}
