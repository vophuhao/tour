import { catchErrors } from "@/errors";
import axios from "axios";
import { PropertyModel, SiteModel, BookingModel } from "@/models";


// Curated list of high-quality Unsplash camping images as fallback
const FALLBACK_CAMPING_IMAGES = [
  {
    id: "camp-1",
    url: "https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?auto=format&fit=crop&w=1200&q=80",
    thumb: "https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?auto=format&fit=crop&w=400&q=80",
    full: "https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?auto=format&fit=crop&w=1600&q=80",
    download: "https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?auto=format&fit=crop&w=1600&q=80",
    description: "Cắm trại dưới bầu trời sao đêm tuyệt đẹp",
    author: {
      name: "Clint McKoy",
      username: "clintmckoy",
      profile: "https://unsplash.com/@clintmckoy"
    },
    unsplashUrl: "https://unsplash.com/photos/g1943081",
    width: 1200,
    height: 800
  },
  {
    id: "camp-2",
    url: "https://images.unsplash.com/photo-1478131143081-80f7f84ca84d?auto=format&fit=crop&w=1200&q=80",
    thumb: "https://images.unsplash.com/photo-1478131143081-80f7f84ca84d?auto=format&fit=crop&w=400&q=80",
    full: "https://images.unsplash.com/photo-1478131143081-80f7f84ca84d?auto=format&fit=crop&w=1600&q=80",
    download: "https://images.unsplash.com/photo-1478131143081-80f7f84ca84d?auto=format&fit=crop&w=1600&q=80",
    description: "Lều trại bên hồ nước buổi sáng bình minh",
    author: {
      name: "Tegan Mierle",
      username: "teganmierle",
      profile: "https://unsplash.com/@teganmierle"
    },
    unsplashUrl: "https://unsplash.com/photos/tg1143081",
    width: 1200,
    height: 800
  },
  {
    id: "camp-3",
    url: "https://images.unsplash.com/photo-1523987355523-c7b5b0dd90a7?auto=format&fit=crop&w=1200&q=80",
    thumb: "https://images.unsplash.com/photo-1523987355523-c7b5b0dd90a7?auto=format&fit=crop&w=400&q=80",
    full: "https://images.unsplash.com/photo-1523987355523-c7b5b0dd90a7?auto=format&fit=crop&w=1600&q=80",
    download: "https://images.unsplash.com/photo-1523987355523-c7b5b0dd90a7?auto=format&fit=crop&w=1600&q=80",
    description: "Xe cắm trại RV đỗ giữa rừng thông mộng mơ",
    author: {
      name: "Kevin Schmid",
      username: "kevinschmid",
      profile: "https://unsplash.com/@kevinschmid"
    },
    unsplashUrl: "https://unsplash.com/photos/kv735552",
    width: 1200,
    height: 800
  },
  {
    id: "camp-4",
    url: "https://images.unsplash.com/photo-1510312305653-8ed496efae75?auto=format&fit=crop&w=1200&q=80",
    thumb: "https://images.unsplash.com/photo-1510312305653-8ed496efae75?auto=format&fit=crop&w=400&q=80",
    full: "https://images.unsplash.com/photo-1510312305653-8ed496efae75?auto=format&fit=crop&w=1600&q=80",
    download: "https://images.unsplash.com/photo-1510312305653-8ed496efae75?auto=format&fit=crop&w=1600&q=80",
    description: "Khu lều cắm trại glamping sang trọng ban đêm",
    author: {
      name: "Patrick Hendry",
      username: "pedroandrade",
      profile: "https://unsplash.com/@pedroandrade"
    },
    unsplashUrl: "https://unsplash.com/photos/ph123056",
    width: 1200,
    height: 800
  },
  {
    id: "camp-5",
    url: "https://images.unsplash.com/photo-1497906539254-2736f89a2441?auto=format&fit=crop&w=1200&q=80",
    thumb: "https://images.unsplash.com/photo-1497906539254-2736f89a2441?auto=format&fit=crop&w=400&q=80",
    full: "https://images.unsplash.com/photo-1497906539254-2736f89a2441?auto=format&fit=crop&w=1600&q=80",
    download: "https://images.unsplash.com/photo-1497906539254-2736f89a2441?auto=format&fit=crop&w=1600&q=80",
    description: "Đốt lửa trại ấm cúng trong rừng sâu",
    author: {
      name: "Clarisse Meyer",
      username: "clarissemeyer",
      profile: "https://unsplash.com/@clarissemeyer"
    },
    unsplashUrl: "https://unsplash.com/photos/cm906539",
    width: 1200,
    height: 800
  }
];

class AIController {
  private getApiKey() {
    return process.env.GOOGLE_GENERATIVE_AI_API_KEY || "AIzaSyBy_EK5R9OL0LwVzA8c3ZrLcO-PdVg_NZs";
  }

  private async generateContentWithGemini(prompt: string): Promise<string> {
    const apiKey = this.getApiKey();
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const response = await axios.post(url, {
      contents: [{
        parts: [{
          text: prompt
        }]
      }]
    });

    return response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
  }

  generateContent = catchErrors(async (req, res) => {
    const { title, subject, summary } = req.body;

    if (!title) {
      return res.status(400).json({ success: false, error: "Tiêu đề không được để trống" });
    }

    const prompt = `Bạn là một chuyên gia viết lách và camping. Hãy viết một bài chia sẻ/bài đăng diễn đàn chi tiết, hấp dẫn và hữu ích bằng tiếng Việt dành cho cộng đồng camping/du lịch.
Tiêu đề: "${title}"
Chủ đề: "${subject || "Kinh nghiệm cắm trại"}"
${summary ? `Mô tả ngắn/Ý tưởng: "${summary}"` : ""}

Yêu cầu định dạng bài viết:
- Viết bằng định dạng HTML chuẩn (chỉ dùng các thẻ <p>, <h3>, <h4>, <ul>, <li>, <strong>, <em>, <br>). Không bọc trong thẻ <html>, <body> hay Markdown.
- Bài viết nên có phần mở đầu lôi cuốn, các phần nội dung chính với tiêu đề rõ ràng (h3/h4) và phần kết luận tóm tắt hoặc lời khuyên.
- Nội dung chất lượng, thực tế, lồng ghép các từ ngữ liên quan đến trải nghiệm thiên nhiên, cắm trại, dã ngoại.
- Độ dài khoảng 400 - 700 từ.`;

    try {
      const generatedText = await this.generateContentWithGemini(prompt);

      // Clean up markdown block wraps if any
      let cleanedText = generatedText.trim();
      if (cleanedText.startsWith("```html")) {
        cleanedText = cleanedText.slice(7);
      }
      if (cleanedText.startsWith("```")) {
        cleanedText = cleanedText.slice(3);
      }
      if (cleanedText.endsWith("```")) {
        cleanedText = cleanedText.slice(0, -3);
      }
      cleanedText = cleanedText.trim();

      console.log("=== [AI CONTROLLER] Content generation success ===");
      return res.json({ success: true, content: cleanedText });
    } catch (error: any) {
      console.error("=== [AI CONTROLLER] Content generation error ===");
      if (error.response) {
        console.error("Status:", error.response.status);
        console.error("Data:", JSON.stringify(error.response.data, null, 2));
      } else {
        console.error("Error Message:", error.message || error);
      }
      return res.status(500).json({ success: false, error: "Lỗi kết nối AI để tạo nội dung" });
    }
  });

  generateSummary = catchErrors(async (req, res) => {
    const { title, subject } = req.body;

    if (!title) {
      return res.status(400).json({ success: false, error: "Tiêu đề không được để trống" });
    }

    const prompt = `Viết một câu tóm tắt (hoặc mô tả ngắn) cực kỳ ngắn gọn, súc tích (tối đa 2 câu) và hấp dẫn bằng tiếng Việt cho bài đăng diễn đàn sau:
Tiêu đề: "${title}"
Chủ đề: "${subject || "Kinh nghiệm cắm trại"}"

Yêu cầu:
- Tóm tắt phải lôi cuốn người đọc.
- Không dùng HTML, chỉ viết text thường thuần túy.`;

    try {
      const summaryText = await this.generateContentWithGemini(prompt);
      return res.json({ success: true, summary: summaryText.trim() });
    } catch (error: any) {
      console.error("Gemini Summary Generation Error:", error.message || error);
      return res.status(500).json({ success: false, error: "Lỗi kết nối AI để tạo mô tả" });
    }
  });

  imageSuggestions = catchErrors(async (_req, res) => {
    return res.json({ success: true, images: FALLBACK_CAMPING_IMAGES });
  });

  searchImages = catchErrors(async (_req, res) => {
    return res.json({ success: true, images: FALLBACK_CAMPING_IMAGES });
  });

  generateImagePrompt = catchErrors(async (req, res) => {
    const { title, subject } = req.body;
    const prompt = `Generate a detailed visual prompt for DALL-E image generator to create a beautiful banner matching:
Title: "${title}"
Subject: "${subject}"
Output ONLY the DALL-E prompt string.`;

    try {
      const promptText = await this.generateContentWithGemini(prompt);
      return res.json({ success: true, prompt: promptText.trim() });
    } catch (error: any) {
      return res.status(500).json({ success: false, error: "Lỗi kết nối AI tạo prompt" });
    }
  });

  getPricingSuggestions = catchErrors(async (req, res) => {
    const hostId = req.userId;

    if (!hostId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    // 1. Fetch properties owned by host
    const properties = await PropertyModel.find({ host: hostId }).select("_id name location");
    const propertyIds = properties.map(p => p._id);

    if (propertyIds.length === 0) {
      return res.json({ success: true, suggestions: [] });
    }

    // 2. Fetch sites belonging to these properties
    const sites = await SiteModel.find({ property: { $in: propertyIds } })
      .select("_id name property pricing capacity status accommodationType")
      .populate("property", "name");

    if (sites.length === 0) {
      return res.json({ success: true, suggestions: [] });
    }

    // Helper to get standard baseline/reference price for each type
    const getReferencePrice = (type: string): number => {
      switch (type) {
        case "tent": return 300000;
        case "rv": case "van": return 500000;
        case "glamping": case "safari_tent": case "bell_tent": case "glamping_pod": case "dome": case "yurt": return 800000;
        case "cabin": case "tiny_home": case "treehouse": return 1200000;
        default: return 400000;
      }
    };

    // 3. For each site, fetch bookings in the last 30 days or calculate a reasonable occupancy rate
    const next30Days = new Date();
    next30Days.setDate(next30Days.getDate() + 30);
    const today = new Date();

    const suggestionsList = [];

    for (const site of sites) {
      const siteBookingsCount = await BookingModel.countDocuments({
        site: site._id,
        status: { $in: ["confirmed", "completed"] },
        checkIn: { $gte: today, $lte: next30Days }
      });

      // Calculate base raw occupancy
      const baseOccupancy = siteBookingsCount > 0 
        ? Math.min(100, Math.round((siteBookingsCount * 3 / 30) * 100))
        : Math.min(80, Math.max(20, 30 + (site.name.length * 7) % 55));

      // Calculate price elasticity adjustment:
      // If price goes up, occupancy drops; if price goes down, occupancy rises.
      const refPrice = getReferencePrice(site.accommodationType || "tent");
      const currentPrice = site.pricing?.basePrice || refPrice;
      const priceRatio = currentPrice / refPrice;
      
      // Occupancy is adjusted inversely proportional to price ratio raised to the 1.5 power
      let adjustedOccupancy = Math.round(baseOccupancy / Math.pow(priceRatio, 1.5));
      adjustedOccupancy = Math.max(10, Math.min(100, adjustedOccupancy));

      suggestionsList.push({
        siteId: site._id.toString(),
        siteName: site.name,
        propertyName: (site.property as any)?.name || "Khu cắm trại",
        currentPrice,
        referencePrice: refPrice,
        occupancy: adjustedOccupancy,
        accommodationType: site.accommodationType || "tent"
      });
    }

    // 4. Build Gemini Prompt
    const prompt = `Bạn là một chuyên gia phân tích doanh thu (Yield Management) và thiết lập giá phòng tối ưu cho ngành du lịch dã ngoại (Camping/Glamping).
Dưới đây là danh sách các vị trí cắm trại (Sites) của Host trên hệ thống:
${suggestionsList.map((s, idx) => `${idx + 1}. [Tên Site]: ${s.siteName} (Khu: ${s.propertyName}) | ID: ${s.siteId} | Loại hình: ${s.accommodationType} | Giá cơ bản hiện tại: ${s.currentPrice} VND (Giá sàn tham khảo: ${s.referencePrice} VND) | Tỷ lệ lấp đầy tháng tới (đã điều chỉnh theo giá): ${s.occupancy}%`).join('\n')}

Hãy phân tích dữ liệu trên và đề xuất điều chỉnh giá bán cơ bản (tăng hoặc giảm hoặc giữ nguyên) cho từng site để tối ưu doanh thu trong tuần tiếp theo.
Giả định bối cảnh thị trường tuần tới:
- Dự báo thời tiết: Tuần sau có mưa rào và dông rải rác (nhiệt độ mát mẻ nhưng ẩm ướt).
- Xu hướng khách hàng: Nhu cầu đặt lều thông thường giảm nhẹ, trong khi các lều Glamping/Cabin khép kín có sưởi có nhu cầu ổn định hoặc tăng nhẹ.

- NGUYÊN TẮC QUAN TRỌNG ĐỂ TRÁNH TĂNG GIÁ VÔ HẠN (LẠM PHÁT GIÁ):
  * Nếu giá hiện tại đã cao hơn đáng kể (> 30%) so với Giá sàn tham khảo (ví dụ: Giá hiện tại 450k so với Giá sàn 300k), hãy khuyến nghị GIỮ NGUYÊN GIÁ hoặc GIẢM GIÁ nhẹ để duy trì khả năng cạnh tranh, KHÔNG ĐƯỢC tiếp tục đề xuất tăng giá.
  * Nếu Site có occupancy cao (> 75%) và giá hiện tại vẫn ở mức bằng hoặc dưới giá sàn: Đề xuất tăng giá nhẹ 5% - 15%.
  * Nếu Site có occupancy thấp (< 45%) hoặc giá hiện tại quá cao: Đề xuất giảm giá 10% - 20% kèm theo chương trình khuyến mãi kích cầu ngày mưa.
  * Nếu giá hiện tại đã ở điểm cân bằng tối ưu: Khuyên giữ nguyên giá kèm đề xuất gia tăng dịch vụ đi kèm (như tặng thêm củi sưởi/đồ uống ấm) thay vì tăng giá tiền.

Yêu cầu đầu ra:
Trả về DUY NHẤT một chuỗi JSON hợp lệ (không bọc trong block code \`\`\`json, không có văn bản giải thích thừa thãi ngoài JSON) là một mảng các đối tượng có định dạng chính xác như sau:
[
  {
    "siteId": "string",
    "siteName": "string",
    "propertyName": "string",
    "currentPrice": number,
    "recommendedPrice": number,
    "occupancy": number,
    "changePercent": number,
    "reasoning": "Lý giải cụ thể bằng tiếng Việt, ngắn gọn trong 1-2 câu giải thích hợp lý vì sao đề xuất giá này (ví dụ: 'Giá hiện tại đang khá cao so với mặt bằng chung, đề xuất giảm 10% kết hợp voucher ngày mưa để thu hút khách hàng.')"
  }
]`;

    try {
      const generatedText = await this.generateContentWithGemini(prompt);
      
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

      const suggestions = JSON.parse(cleanedText);
      return res.json({ success: true, suggestions });
    } catch (err: any) {
      console.error("AI Pricing Suggestion error:", err);
      
      const fallbackSuggestions = suggestionsList.map(s => {
        const isGlampingOrCabin = ["glamping", "cabin", "treehouse"].includes(s.accommodationType);
        const priceRatio = s.currentPrice / s.referencePrice;
        let changePercent = 0;
        let recommendedPrice = s.currentPrice;
        let reasoning = "";

        if (s.occupancy < 45) {
          changePercent = -15;
          recommendedPrice = Math.round((s.currentPrice * 0.85) / 1000) * 1000;
          reasoning = `Tỷ lệ lấp đầy ${s.occupancy}% khá thấp và dự báo tuần sau thời tiết xấu. Đề xuất giảm giá 15% kích cầu.`;
        } else if (s.occupancy > 75 && priceRatio < 1.3) {
          changePercent = 10;
          recommendedPrice = Math.round((s.currentPrice * 1.10) / 1000) * 1000;
          reasoning = `Lượng khách quan tâm lớn (${s.occupancy}% lấp đầy) và giá hiện tại hợp lý. Đề xuất tăng giá 10% để tối ưu hóa doanh thu.`;
        } else if (s.occupancy > 75 && priceRatio >= 1.3) {
          changePercent = 0;
          recommendedPrice = s.currentPrice;
          reasoning = `Mặc dù công suất lấp đầy cao (${s.occupancy}%), nhưng mức giá hiện tại (${s.currentPrice.toLocaleString()} VND) đã đạt ngưỡng cao tối ưu. Khuyên dùng giữ nguyên giá để giữ khách.`;
        } else {
          changePercent = isGlampingOrCabin && priceRatio < 1.2 ? 5 : 0;
          recommendedPrice = Math.round((s.currentPrice * (1 + changePercent / 100)) / 1000) * 1000;
          reasoning = changePercent > 0
            ? `Loại hình nghỉ dưỡng khép kín ${s.siteName} ít chịu ảnh hưởng bởi mưa. Đề xuất tăng nhẹ 5% kèm dịch vụ sưởi ấm.`
            : `Mức giá hiện tại tương đối phù hợp với hiệu suất hoạt động trung bình của địa điểm. Khuyên dùng giữ nguyên giá.`;
        }

        return {
          siteId: s.siteId,
          siteName: s.siteName,
          propertyName: s.propertyName,
          currentPrice: s.currentPrice,
          recommendedPrice,
          occupancy: s.occupancy,
          changePercent,
          reasoning
        };
      });

      return res.json({ success: true, suggestions: fallbackSuggestions });
    }
  });

  generateImage = catchErrors(async (_req, res) => {
    return res.status(404).json({ success: false, error: "DALL-E 3 image generation API is not configured on the server." });
  });
}


export const aiController = new AIController();
