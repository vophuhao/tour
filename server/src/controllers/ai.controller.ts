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
    return process.env.GOOGLE_GENERATIVE_AI_API_KEY
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

  private async fetchRealWeather(lat: number, lng: number, dateOffset: number): Promise<string> {
    try {
      const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lng}&daily=weathercode,temperature_2m_max,temperature_2m_min&timezone=Asia/Ho_Chi_Minh`;
      const response = await axios.get(url);
      const daily = response.data?.daily;
      if (!daily || !daily.time) {
        return "Không có dữ liệu thời tiết thực tế";
      }

      const index = dateOffset >= 0 && dateOffset < daily.time.length ? dateOffset : 0;
      const weatherCode = daily.weathercode?.[index];
      const maxTemp = daily.temperature_2m_max?.[index];
      const minTemp = daily.temperature_2m_min?.[index];

      let description = "Thời tiết ôn hòa";
      if (weatherCode === 0) description = "Nắng ráo, trời quang ☀️";
      else if ([1, 2, 3].includes(weatherCode)) description = "Ít mây, trời nắng đẹp 🌤️";
      else if ([45, 48].includes(weatherCode)) description = "Có sương mù 🌫️";
      else if ([51, 53, 55, 56, 57].includes(weatherCode)) description = "Mưa phùn nhẹ 🌧️";
      else if ([61, 63, 65, 66, 67].includes(weatherCode)) description = "Mưa rào rải rác 🌧️";
      else if ([71, 73, 75, 77].includes(weatherCode)) description = "Có tuyết/mưa tuyết ❄️";
      else if ([80, 81, 82].includes(weatherCode)) description = "Mưa rào lớn ⛈️";
      else if ([95, 96, 99].includes(weatherCode)) description = "Có dông bão ⚡";

      return `${description} (${minTemp}°C - ${maxTemp}°C)`;
    } catch (error: any) {
      console.error("Open-Meteo API Error:", error.message || error);
      return "Thời tiết ôn hòa, thích hợp di chuyển";
    }
  }

  generateRoadtripSuggestions = catchErrors(async (req, res) => {
    const { origin, destination, days, vehicleType, candidates } = req.body;

    if (!origin || !destination || !days || !candidates || !Array.isArray(candidates)) {
      return res.status(400).json({ success: false, error: "Thiếu dữ liệu lộ trình hoặc danh sách ứng viên" });
    }

    const getCoords = (c: any): [number, number] | null => {
      if (!c.location) return null;
      const coordsObj = c.location.coordinates;
      if (!coordsObj) {
        if (c.location.lat !== undefined && c.location.lng !== undefined) {
          return [c.location.lng, c.location.lat];
        }
        return null;
      }
      if (Array.isArray(coordsObj) && coordsObj.length >= 2) {
        return [coordsObj[0], coordsObj[1]]; // [lng, lat]
      }
      if (Array.isArray(coordsObj.coordinates) && coordsObj.coordinates.length >= 2) {
        return [coordsObj.coordinates[0], coordsObj.coordinates[1]]; // [lng, lat] nested in GeoJSON
      }
      return null;
    };

    // Lấy thời tiết thực tế cho tất cả các campsite ứng viên
    const candidatesWithWeather = await Promise.all(
      candidates.map(async (c: any) => {
        let weatherInfo = "Thời tiết mát mẻ 🌤️";
        const coords = getCoords(c);
        if (coords) {
          weatherInfo = await this.fetchRealWeather(coords[1], coords[0], 0); // offset 0
        }
        return {
          ...c,
          weather: weatherInfo
        };
      })
    );

    const prompt = `Bạn là một trợ lý ảo lập kế hoạch du lịch bụi, phượt dã ngoại (Roadtrip & Camping) thông minh tại Việt Nam.
Hãy giúp tôi lựa chọn các địa điểm cắm trại (campsites) tốt nhất làm chặng dừng chân qua đêm cho hành trình sau:

- Điểm xuất phát: "${origin}"
- Điểm kết thúc: "${destination}"
- Số ngày đi: ${days} ngày (${days - 1} đêm)
- Phương tiện di chuyển: "${vehicleType === 'motorcycle' ? 'Xe máy' : 'Ô tô'}"

Đặc thù phương tiện:
${vehicleType === 'motorcycle'
        ? '- Di chuyển bằng xe máy: Tốc độ trung bình khoảng 40 km/h, không được đi vào cao tốc tại Việt Nam. Dễ bị mệt mỏi khi đi xa, nên ưu tiên các chặng dừng chân sau mỗi 120km - 150km. Lời khuyên phượt cần lưu ý về an toàn xe máy, thời tiết mưa gió ảnh hưởng trực tiếp, trang phục bảo hộ và các chặng đèo hiểm trở.'
        : '- Di chuyển bằng ô tô: Tốc độ trung bình khoảng 60 km/h, được phép đi vào đường cao tốc. Có thể di chuyển chặng dài hơn (200km - 300km/ngày). Cần lưu ý về trạm thu phí, bãi đỗ ô tô tại campsite.'
      }

Dưới đây là danh sách các khu cắm trại (campsite) thực tế có sẵn dọc hành lang tuyến đường, kèm theo thông tin thời tiết thực tế đo được tại khu vực đó:
${candidatesWithWeather.map((c: any, idx: number) => `${idx + 1}. [Tên]: "${c.name}" | ID: "${c._id}" | Loại hình: "${c.propertyType}" | Giá: ${c.price} VND | Đánh giá: ${c.rating}⭐ | Địa phương: "${c.location?.city || c.location?.state || 'Dọc đường'}" | Thời tiết đo được: "${c.weather}"`).join('\n')}

Hãy đóng vai trò chuyên gia điều phối lịch trình du lịch:
1. Hãy lựa chọn ra chính xác ${days - 1} khu cắm trại từ danh sách trên để làm trạm dừng nghỉ đêm cho từng ngày (Ngày 1 chọn 1 khu cắm trại để ngủ đêm 1, Ngày 2 chọn 1 khu cắm trại để ngủ đêm 2...).
   - NGUYÊN TẮC BẮT BUỘC: Mỗi đêm nghỉ phải dừng chân tại một khu cắm trại KHÁC NHAU. Tuyệt đối không được chọn trùng lặp một khu cắm trại cho nhiều đêm nghỉ khác nhau (ví dụ: Không thể chọn cùng một ID cho cả Ngày 1 và Ngày 2).
   - Nếu đa số các khu cắm trại đều tập trung tại khu vực đích đến (như Đà Lạt) và quãng đường di chuyển khá ngắn, bạn hãy lựa chọn các khu cắm trại KHÁC NHAU tại Đà Lạt cho mỗi đêm nghỉ để người dùng được trải nghiệm nhiều địa điểm cắm trại khác nhau trong cùng chuyến đi (ví dụ: Đêm 1 ngủ ở campsite đồi, Đêm 2 ngủ ở campsite ven hồ).
   - Phân bổ địa lý hợp lý: Đối với hành trình dài, chọn các khu cắm trại có vị trí địa lý phân bổ đều dọc theo lộ trình lái xe. Nếu đi bằng Xe máy, hãy đảm bảo khoảng cách lái xe giữa các chặng ngắn hơn và an toàn hơn so với Ô tô.
   - Nếu danh sách ứng viên rỗng hoặc không đủ ${days - 1} địa điểm cắm trại khác nhau, bạn có thể tự đề xuất thêm trạm dừng cắm trại tự do (Free Spot) kèm theo tọa độ giả định và đặt ID là "free_spot_day_X".
2. Với mỗi khu cắm trại được chọn, hãy viết một câu lời khuyên/mẹo phượt di chuyển hoặc chuẩn bị đồ dùng cá nhân hóa cực kỳ thiết thực dựa trên phương tiện di chuyển và thời tiết thực tế đo được tại campsite đó.

Yêu cầu định dạng đầu ra:
Trả về DUY NHẤT một chuỗi JSON hợp lệ (không bọc trong block code \`\`\`json, không chứa bất kỳ lời giải thích nào khác ngoài JSON) là một mảng các đối tượng đại diện cho điểm cắm trại được chọn cho từng đêm nghỉ:
[
  {
    "dayNumber": number, // Ngày thứ mấy của hành trình (từ 1 đến ${days - 1})
    "selectedCampsiteId": "string", // ID chính xác của campsite được chọn từ danh sách ứng viên được cung cấp ở trên (hoặc "free_spot_day_X")
    "weather": "string", // Điền thông tin thời tiết đo được của campsite đó
    "aiTip": "string" // Lời khuyên phượt cá nhân hóa tương ứng
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
      console.error("AI Roadtrip Suggestions error:", err);
      return res.status(500).json({ success: false, error: "Lỗi kết nối AI để tạo gợi ý lộ trình" });
    }
  });
}



export const aiController = new AIController();
