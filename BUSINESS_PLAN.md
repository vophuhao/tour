# HDCamp — Business Plan
> Nền tảng đặt chỗ cắm trại & nghỉ dưỡng ngoài trời Việt Nam (tương tự Hipcamp)
> Phiên bản: 1.0 | Ngày: 01/03/2026

---

## Tổng quan

HDCamp là nền tảng **marketplace 2 phía** kết nối Camper (người đặt chỗ) và Host (chủ đất/campground) trong lĩnh vực cắm trại và nghỉ dưỡng ngoài trời.

| Hạng mục | Quyết định |
|---|---|
| Thị trường | Việt Nam trước, mở rộng quốc tế sau |
| Vai trò người dùng | Camper, Host (dual role), Admin |
| Loại chỗ ở | 6 loại: Tent, Glamping, Cabin, RV, Treehouse/Yurt, Homestay nông trại |
| Booking flow | Host chọn per site: Instant Book hoặc Request to Book |
| Site mode | Designated (vị trí cố định) hoặc Undesignated (khu vực chung, multi-slot) |
| Thanh toán | VNPay/MoMo/ZaloPay trước, Stripe sau |
| Huỷ/Hoàn tiền | Host chọn 1 trong 3 tier: Flexible / Moderate / Strict |
| Mô hình doanh thu | Split fee: service fee (Camper) + commission (Host) |
| Review | 2 chiều: Camper ↔ Host, ẩn đến khi cả 2 viết xong |
| Xác minh Host | 3 cấp: eKYC → Admin review listing → Verified badge (optional) |
| Messaging | Chat nâng cao: text + ảnh + scheduled messages |
| Tìm kiếm | Địa danh + Map + Filters + Roadtrip planner + Trending |
| Pricing | Dynamic: weekday/weekend/holiday + giảm dài ngày + phí bổ sung |
| Thông báo | Email + Push notification (mobile) + In-app notification |
| Tính năng đặc thù VN | Add-on trải nghiệm + Cho thuê dụng cụ camping |

---

## Module 1: Xác thực (Auth)

### 1.1 Đăng ký / Đăng nhập
- Đăng ký bằng Email hoặc Số điện thoại
- Đăng nhập Social: Google, Facebook, Apple
- Xác thực OTP qua SMS / Email
- Quên mật khẩu / Đổi mật khẩu
- Refresh token (keep session alive)

---

## Module 2: Hồ sơ người dùng & Dual Role (User Profile)

### 2.1 Hồ sơ người dùng (Profile)
- Thông tin cá nhân: tên, avatar, bio, ngôn ngữ, tiền tệ ưa thích
- Lịch sử chuyến đi (Camper) / Lịch sử hosting (Host)
- Badge hiển thị: Verified Host, Superhost, số chuyến đi

> **MVP note (v1 backend):**
> - Hiển thị đầy đủ thông tin cá nhân + trạng thái vai trò hiện tại (active role).
> - `Verified Host` triển khai ngay khi hoàn thành KYC cấp 3.
> - `Superhost` và thống kê lịch sử chuyến đi/hosting chi tiết sẽ triển khai khi Module Booking + Review hoàn tất dữ liệu nguồn.

### 2.2 Dual Role (Camper ↔ Host)
- 1 tài khoản có thể chuyển đổi vai trò, không cần tạo 2 tài khoản riêng
- Khi bật vai trò Host: bắt buộc đi qua luồng xác minh Host (Module 3)

### 2.3 Superhost Program (ảnh hưởng ranking ngay từ v1)

Superhost được tính tự động hàng tháng theo các tiêu chí (tham khảo Airbnb):

| Tiêu chí | Ngưỡng |
|---|---|
| Rating tổng thể | ≥ 4.8 sao |
| Tỷ lệ phản hồi tin nhắn | ≥ 90% trong 24h |
| Tỷ lệ chấp nhận Request to Book | ≥ 90% |
| Số booking hoàn thành | ≥ 10 booking / năm |
| Tỷ lệ huỷ (bởi Host) | ≤ 1% (tối đa 1 lần / năm) |

- Badge Superhost hiển thị trên profile và listing
- Superhost được **boost ranking** trên Search (Module 7)
- Badge mất nếu không đạt tiêu chí vào kỳ đánh giá tiếp theo

> **MVP note (v1 backend):** Superhost được giữ trong business spec nhưng **defer implementation** ở backend hiện tại cho đến khi có dữ liệu booking/review/message đầy đủ và scheduler đánh giá định kỳ.

> **Admin actions:** Xem chi tiết profile, ban / suspend / reactivate account, reset password, gửi email xác minh lại.

---

## Module 3: Xác minh Host (Host Verification / KYC)

### 3.1 Luồng xác minh 3 cấp

| Cấp | Yêu cầu | Bắt buộc? | Cách xử lý |
|---|---|---|---|
| Cấp 1 | Email + SĐT verified + CMND/CCCD | ✅ Bắt buộc | MVP: upload hồ sơ + Admin duyệt thủ công. Giai đoạn sau: eKYC tự động |
| Cấp 2 | Review listing đầu tiên | ✅ Bắt buộc khi tạo listing | Auto-check cơ bản + Admin duyệt thủ công |
| Cấp 3 | Upload giấy tờ đất / GPKD | ❌ Tuỳ chọn | Admin duyệt → gắn "Verified Host" badge |

> **MVP note (v1 backend):**
> - Cấp 1 dùng quy trình manual review để giảm rủi ro tích hợp eKYC sớm.
> - Cấp 2 có thể chạy qua verification ticket nội bộ trước khi module Listing hoàn thiện đầy đủ.
> - Cấp 3 triển khai đầy đủ vì liên quan trực tiếp badge `Verified Host`.

> **Admin actions:** Duyệt / từ chối hồ sơ KYC cấp 2 & cấp 3, gắn/gỡ badge "Verified Host".

---

## Module 4: Quản lý Property & Listing (Host)

### 4.1 Cấu trúc Property → Sites
- 1 **Property** (khu đất / campground) chứa nhiều **Sites** (điểm cắm trại riêng lẻ)
- **Property:** tên, mô tả, địa chỉ, toạ độ GPS, quy tắc chung, ảnh cover
- **Site:** tên, loại chỗ ở, mô tả, ảnh, sức chứa (max guests), tiện nghi, chính sách

### 4.1.1 Site Mode: Designated vs Undesignated

Host chọn **site mode** khi tạo Site. Mỗi Site trong cùng Property có thể có mode khác nhau.

| | **Designated Site** | **Undesignated Site** |
|---|---|---|
| Định nghĩa | Vị trí cụ thể, cố định (VD: "Site A cạnh suối") | Khu vực chung, không phân chia vị trí cụ thể (VD: "Bãi cỏ lớn") |
| Camper thấy gì | Biết chính xác chỗ mình sẽ ở | Chỉ biết khu vực, Host assign vị trí khi check-in |
| Capacity | 1 booking tại 1 thời điểm per site | Nhiều booking đồng thời — Host cấu hình `max_simultaneous_bookings` |
| Giá | Per site / đêm | Per group (per booking) / đêm |
| Calendar | Block/available per site | Hiển thị còn X / N slot available mỗi ngày |
| Ảnh / Mô tả | Ảnh & mô tả riêng cho site cụ thể | Ảnh & mô tả chung cho khu vực |
| Phù hợp cho | Cabin, Glamping, Treehouse, RV bay cố định | Tent site bãi rộng, đồng cỏ, khu camping tự do |

**Designated Site — chi tiết:**
- Mỗi site có tên/số riêng biệt ("Site 1", "Vị trí Ven Hồ")
- Camper chọn site cụ thể khi đặt → biết trước vị trí, ảnh, tiện nghi riêng
- Tối đa 1 booking active per site tại 1 thời điểm
- Lý tưởng cho chỗ ở có tiện nghi cố định (Cabin, Glamping, Treehouse)

**Undesignated Site — chi tiết:**
- Đại diện cho 1 **khu vực** chung, không chia thành các vị trí riêng lẻ
- Host cấu hình `max_simultaneous_bookings` (VD: bãi cỏ 2ha nhận tối đa 10 nhóm/đêm)
- Camper đặt chỗ trong khu vực → Host sắp xếp vị trí cụ thể khi check-in
- Đơn vị tính giá linh hoạt: per group, per tent, hoặc per vehicle
- Lý tưởng cho bãi cắm lều rộng, khu đất trống không cố định chỗ

### 4.2 Loại chỗ ở (Site Types)
- Tent site (Bãi cắm lều tự dựng)
- Glamping (Lều sang trọng dựng sẵn, có tiện nghi)
- Cabin / Nhà gỗ
- RV site (Bãi đỗ xe cắm trại)
- Treehouse / Yurt / Đặc biệt
- Homestay nông trại (ở tại nông trại, vườn cây, trang trại)

### 4.3 Tiện nghi & Đặc điểm (Amenities & Features)

| Nhóm | Chi tiết |
|---|---|
| Tiện nghi cơ bản | Nhà vệ sinh, nước uống, điện, WiFi, bếp, bãi đỗ xe |
| Hoạt động | Leo núi, câu cá, bơi, kayak, đạp xe, ngắm sao |
| Đặc điểm tự nhiên | Ven suối, ven hồ, trên đồi, trong rừng, view núi |
| Phù hợp cho | Gia đình, cặp đôi, nhóm bạn, team building |
| Quy tắc | Cho phép thú cưng, lửa trại, hút thuốc, giờ yên tĩnh |

### 4.4 Trải nghiệm bổ sung (Add-on Experiences)
- Host tạo các trải nghiệm đi kèm: tour trekking, BBQ party, lớp nấu ăn farm-to-table...
- Mỗi trải nghiệm bao gồm: tên, mô tả, giá, thời lượng, số người tối đa, lịch available
- Camper có thể thêm khi đặt chỗ hoặc đặt riêng (standalone)

### 4.5 Cho thuê dụng cụ (Equipment Rental)
- Host liệt kê dụng cụ cho thuê: lều, túi ngủ, ghế, bếp, đèn pin...
- Mỗi item bao gồm: tên, ảnh, giá/đêm, số lượng tồn kho
- Camper thêm vào booking khi đặt chỗ hoặc đặt riêng

### 4.6 Chính sách hoàn tiền cho Add-on & Equipment khi huỷ

| Thời điểm huỷ | Add-on Experience | Equipment Rental |
|---|---|---|
| Trước 48h check-in | Hoàn 100% | Hoàn 100% |
| Trong vòng 48h check-in | Hoàn 0% | Hoàn 100% (nếu chưa chuẩn bị) / 0% (nếu đã chuẩn bị) |
| Host cancel | Hoàn 100% | Hoàn 100% |

- Equipment Rental: Host xác nhận trạng thái "đã chuẩn bị" trước 24h check-in → trigger lock chính sách hoàn tiền
- Policy này **độc lập** với tier huỷ của site booking (Flexible/Moderate/Strict)

> **Admin actions:** Duyệt / từ chối listing khi Host submit (Cấp 2 KYC). Approve / Reject kèm lý do gửi về Host. Ẩn / xoá listing vi phạm. Quản lý danh mục tiện nghi, loại chỗ ở, hoạt động, đặc điểm tự nhiên.

---

## Module 5: Quản lý Giá (Pricing)

### 5.1 Dynamic Pricing Model

| Loại giá | Mô tả |
|---|---|
| Giá cơ bản / đêm | Base price per night |
| Giá cuối tuần | Weekend rate (Thứ 6, Thứ 7, Chủ nhật) |
| Giá ngày lễ | Holiday rate — tự động theo lịch lễ VN hoặc Host tuỳ chỉnh |
| Giảm giá dài ngày | Ở 3+ đêm giảm X%, 7+ đêm giảm Y% |
| Phí khách thêm | Extra guest fee (từ người thứ N trở lên) |
| Phí thú cưng | Pet fee per stay |
| Phí xe thêm | Extra vehicle fee |

### 5.2 Quy tắc đặt chỗ
- Min / Max đêm (số đêm tối thiểu/tối đa được đặt)
- Advance notice (yêu cầu báo trước ít nhất X ngày)
- Window booking (chỉ cho đặt trong vòng X tháng tới)

> **Admin actions:** Cấu hình % service fee (Camper) và % commission (Host) — có thể theo loại chỗ ở.

---

## Module 6: Lịch & Availability (Calendar)

### 6.1 Calendar Management
- Xem lịch dạng tháng: từng ngày hiển thị booking / blocked / available
- Block / unblock từng ngày hoặc khoảng ngày
- Đổi giá từng ngày cụ thể trực tiếp trên calendar
- Đóng / mở theo mùa (pause site / pause property)
- **Calendar sync 2 chiều (iCal):** import/export .ics để tránh double booking với các platform khác (Airbnb, Booking.com...)

### 6.2 Calendar theo Site Mode

| | Designated | Undesignated |
|---|---|---|
| Trạng thái ngày | Booked / Blocked / Available | X / N slots available (VD: 3/10 còn trống) |
| Block ngày | Block toàn bộ site | Block toàn bộ khu vực hoặc giảm số slot |
| iCal sync | 1 feed per site | 1 feed per khu vực (aggregate) |

---

## Module 7: Tìm kiếm (Search)

### 7.1 Tìm kiếm theo địa danh
- Tìm theo tỉnh/thành, vùng, huyện/xã
- Autocomplete gợi ý khi gõ
- Tìm theo từ khoá tự do (tên campsite)

### 7.2 Tìm kiếm trên bản đồ (Map Search)
- Bản đồ tương tác, kéo/zoom → auto-load kết quả trong viewport
- Cluster markers khi zoom out
- Click marker → xem preview listing (ảnh, tên, giá, rating)

### 7.3 Bộ lọc chi tiết (Filters)
- Loại chỗ ở (Tent / Glamping / Cabin / RV / Treehouse / Homestay)
- Khoảng giá (min – max / đêm)
- Số khách (người lớn + trẻ em)
- Tiện nghi (WiFi, điện, nhà vệ sinh, bếp...)
- Hoạt động (leo núi, câu cá, kayak...)
- Đặc điểm tự nhiên (ven hồ, trong rừng...)
- Rating tối thiểu
- Instant Book only
- Có cho thuê dụng cụ
- Có trải nghiệm add-on
- Cho phép thú cưng

### 7.4 Roadtrip Planner
- Nhập điểm xuất phát → điểm đến
- Gợi ý campsite dọc tuyến đường theo bán kính tuỳ chọn
- Xem trên bản đồ dạng route kết hợp danh sách

---

## Module 8: Khám phá & Gợi ý (Discovery & Recommendations)

> Tách riêng khỏi Search vì đây là recommendation engine chạy async, không phải query đồng bộ.

### 8.1 Gợi ý & Trending
- Campsite phổ biến gần vị trí hiện tại
- Mới đăng, đánh giá cao, đang trending
- Theo mùa/thời điểm (mùa hè → biển, mùa đông → núi)
- Available tonight / this weekend / next weekend
- Recently viewed (lịch sử xem của Camper)

> **Admin actions:** Quản lý banner/hero section homepage. Featured listings: chọn campsite hiển thị nổi bật. Collections theo chủ đề: "Camping ven biển VN", "Top 10 Đà Lạt".

---

## Module 9: Đặt chỗ (Booking)

### 9.1 Hai luồng đặt chỗ (Host chọn per site)

**Instant Booking:**
```
Camper chọn ngày & số khách
       ↓
Thêm add-on (nếu có)
       ↓
Xác nhận tổng tiền
       ↓
Thanh toán
       ↓
Booking confirmed tự động
       ↓
Thông báo cho cả 2 bên
```

**Request to Book:**
```
Camper gửi yêu cầu + ghi chú (KHÔNG giữ tiền lúc này)
       ↓
Host nhận thông báo (có 24 giờ để phản hồi)
       ↓
Host Accept / Decline / [timeout sau 24h]
       ↓ (Accept)          ↓ (Decline/Timeout)
Camper nhận thông báo   → Trạng thái: Expired
→ thanh toán trong 2h
       ↓ (không thanh toán sau 2h)
    Expired                Expired
       ↓ (thanh toán thành công)
    Booking confirmed
```

- **Không giữ tiền** (pre-authorize) trong lúc chờ Host phản hồi — khác Airbnb, tránh phức tạp khi mới ra mắt
- Timeout 24h: tự động chuyển sang `Expired`, Camper được thông báo để tìm chỗ khác
- Camper có **2h** để thanh toán sau khi Host accept, quá hạn → `Expired`

### 9.2 Thông tin booking
- Site đã chọn, ngày check-in / check-out, số đêm
- **Designated:** hiển thị tên site cụ thể (VD: "Site 3 — Ven Suối")
- **Undesignated:** hiển thị tên khu vực + ghi chú "Host sẽ sắp xếp vị trí khi check-in"
- Số khách: người lớn + trẻ em
- Add-on: trải nghiệm bổ sung + dụng cụ thuê
- Tổng tiền breakdown:
  - Giá site × số đêm
  - Phí bổ sung (extra guest, pet, vehicle)
  - Add-on (trải nghiệm + dụng cụ)
  - Service fee (Camper)
  - Tổng cộng
- Ghi chú gửi cho Host

### 9.3 Trạng thái booking (State Machine)

```
[Instant Book]                    [Request to Book]
Camper thanh toán                 Camper gửi request
       ↓                                 ↓
  Confirmed ←──── Host accept ── Pending Request
                                         ↓ Host decline / timeout (24h) / Camper không TT trong 2h
                                       Expired
  Confirmed
       ↓ (check-in date)
    Ongoing
       ↓ (check-out date)
    Completed

Bất kỳ lúc nào khi Confirmed / Ongoing (trước check-out):
    → Cancelled by Camper  → tính refund theo Module 10
    → Cancelled by Host    → hoàn 100% cho Camper
    → Refunded (xử lý theo Module 11)

Sau check-out:
    → Dispute (trong vòng 48h) → xem Module 10.5
```

### 9.4 Quản lý booking — Host
- Danh sách: upcoming / ongoing / past
- Accept / Decline request (cho Request to Book)
- Cancel booking (có penalty nếu cancel gần ngày)
- Xem thông tin khách: tên, SĐT, số người, ghi chú, lịch sử của khách

**Di chuyển booking (Move booking) sang site khác cùng property:**
- Điều kiện được phép move: site gốc bị sự cố kỹ thuật / thiên tai / không thể sử dụng
- Camper phải được **thông báo và đồng ý** trước khi move
- Giá **giữ nguyên** — không tính thêm dù site mới có giá cao hơn
- Nếu Camper không đồng ý move → Host phải cancel (áp penalty Module 10.2)
- Không được move sang property khác, chỉ cùng property

### 9.5 Quản lý booking — Camper
- Danh sách chuyến đi: sắp tới / đang diễn ra / đã qua
- Xem chi tiết booking, hướng dẫn đến nơi, thông tin liên hệ Host
- Huỷ booking (theo chính sách đã chọn)
- Đề xuất đổi ngày (Host có thể accept/decline)
- Download voucher / xác nhận booking (PDF)

> **Admin actions:** Xem chi tiết tranh chấp booking, liên hệ 2 bên, can thiệp di chuyển booking, ra quyết định hoàn tiền.

---

## Module 10: Chính sách Huỷ (Cancellation Policy)

### 10.1 Host chọn mức chính sách (3 tiers)

| Tier | Tên | Điều kiện hoàn tiền |
|---|---|---|
| Tier 1 | **Flexible** | Huỷ trước 24h → hoàn 100%. Sau 24h → hoàn 50% |
| Tier 2 | **Moderate** | Huỷ trước 5 ngày → hoàn 100%. 1–5 ngày → 50%. Dưới 24h → 0% |
| Tier 3 | **Strict** | Huỷ trước 14 ngày → hoàn 50%. Sau → 0% |

- Host chọn 1 tier áp dụng cho toàn property (hoặc per site)
- Service fee của platform: **không hoàn trong mọi trường hợp**, ngoại trừ:
  - Host cancel (hoàn 100% kể cả service fee — xem Module 10.2)
  - Force Majeure được Admin xác nhận (xem Module 10.4)

### 10.2 Huỷ bởi Host — Host Penalty System
- Camper hoàn 100% (bao gồm service fee)
- Penalty theo tần suất huỷ (tham khảo Airbnb):

| Số lần huỷ (rolling 12 tháng) | Penalty |  
|---|---|
| Lần 1 | Cảnh báo + nhắc nhở qua email |
| Lần 2–3 | Giảm ranking search tạm thời (30 ngày) |
| Lần 4–5 | Giảm ranking search dài hạn (90 ngày) + không được tạo listing mới |
| Từ lần 6+ | Suspend account Host, Admin review thủ công để reactivate |

- Huỷ do bất khả kháng (Admin xác nhận) → **không tính penalty**
- Host không phản hồi Request to Book (timeout 24h, xảy ra ≥ 3 lần/tháng) → cảnh báo, sau đó ép chuyển về Instant Book

### 10.3 Đổi ngày (Date Change)
- Camper có thể đề xuất đổi ngày **trước 48h check-in**
- Host có **24h** để chấp nhận / từ chối
- Nếu giá ngày mới **cao hơn** → Camper trả thêm phần chênh lệch
- Nếu giá ngày mới **thấp hơn** → hoàn tiền phần chênh lệch (theo SLA Module 11.4)
- Đổi ngày **không tính là huỷ** → không áp cancellation tier
- Nếu Host từ chối đổi ngày → Camper vẫn có thể huỷ theo tier thông thường

### 10.4 Xử lý bất khả kháng (Force Majeure)
- Điều kiện: thiên tai, dịch bệnh được công nhận chính thức, lệnh cấm đi lại của Chính phủ
- Camper hoặc Host submit bằng chứng → Admin xác nhận
- Kết quả: hoàn 100% cho Camper (trừ phí xử lý cổng thanh toán nếu có), Host không bị penalty

### 10.5 Tranh chấp (Dispute Resolution)

```
Ai có thể raise? Camper HOẶC Host
Deadline raise:  Trong vòng 48h sau check-out

Camper/Host raise dispute
       ↓
Admin nhận (SLA: xử lý trong 3 ngày làm việc)
       ↓
Admin yêu cầu bằng chứng từ 2 bên (deadline: 48h)
       ↓ (đủ bằng chứng)        ↓ (1 bên không cung cấp)
Admin ra quyết định          Bên không cung cấp thua mặc định
       ↓
Hoàn tiền: Full / Partial (50%) / 0%
       ↓
Không có kháng cáo — quyết định Admin là cuối cùng
       ↓
Thông báo cho cả 2 bên
```

- Host bị kết luận vi phạm: tính như 1 lần Host cancel (áp penalty Module 10.2)
- Camper bị kết luận vi phạm (phá hoại tài sản...): có thể bị suspend account

---

## Module 11: Thanh toán, Payout & Hoàn tiền (Payment, Payout & Refund)

### 11.1 Thu tiền từ Camper
- **Ưu tiên VN:** VNPay, MoMo, ZaloPay
- **Thẻ quốc tế:** Visa/Mastercard (qua VNPay hoặc Stripe sau khi mở rộng)
- **Chuyển khoản ngân hàng nội địa**
- Tiền giữ trong escrow → **release cho Host vào T+1 ngày làm việc sau check-out** (tham khảo Hipcamp/Airbnb)
- Lý do chọn sau check-out (không phải check-in): cho phép xử lý dispute trong khoảng thời gian khách đang ở

### 11.2 Payout cho Host
- Payout định kỳ: hàng tuần hoặc 2 tuần/lần (cấu hình bởi Admin)
- Phương thức: chuyển khoản ngân hàng VN
- Tự động trừ commission trước khi payout
- Lịch sử payout chi tiết, download báo cáo (CSV/PDF)

### 11.3 Mô hình Split Fee

```
Camper trả:   Giá niêm yết + Service fee (X%)
Host nhận:    Giá niêm yết − Commission (Y%)
Platform thu: Service fee (X%) + Commission (Y%)
```

- Admin cấu hình % linh hoạt trong Admin Panel
- Hiển thị minh bạch breakdown cho Camper trước khi thanh toán

### 11.4 Xử lý Hoàn tiền (Refund Processing)
- Tính toán số tiền hoàn dựa theo tier chính sách huỷ (Module 10) và thời điểm huỷ
- Hoàn tiền tự động về phương thức thanh toán gốc khi điều kiện đáp ứng
- Hoàn tiền thủ công bởi Admin trong trường hợp bất khả kháng hoặc tranh chấp
- Ghi nhận lý do huỷ + thời gian xử lý hoàn tiền
- Thông báo kết quả hoàn tiền cho Camper (xem Module 14)

**SLA hoàn tiền cam kết với user:**

| Phương thức thanh toán | Thời gian hoàn tiền thực tế | Cam kết hiển thị với user |
|---|---|---|
| MoMo / ZaloPay / VNPay QR | 1–3 ngày làm việc | 3 ngày làm việc |
| Visa/Mastercard qua VNPay | 7–15 ngày | 15 ngày làm việc |
| Chuyển khoản ngân hàng | 1–2 ngày làm việc | 3 ngày làm việc |

- Nếu quá SLA → Camper có thể liên hệ Support, Admin xử lý thủ công
- Phí xử lý giao dịch của cổng thanh toán (nếu có) do **Platform chịu**, không trừ vào số tiền hoàn của Camper

> **Admin actions:** Cấu hình thời gian escrow release. Cấu hình payout schedule. Xử lý hoàn tiền thủ công. Xem lịch sử giao dịch toàn platform.

---

## Module 12: Nhắn tin (Messaging)

> **Ranh giới với Module 14:** Module 12 quản lý nội dung hội thoại giữa người dùng. Scheduled Messages và Broadcast là automation tạo ra **tin nhắn trong hội thoại** — việc gửi thông báo đẩy ra ngoài (Email/Push/In-app) do Module 14 đảm nhiệm.

### 12.1 Inbox giữa Camper & Host
- Chat real-time (WebSocket)
- Hỗ trợ: text + gửi ảnh
- Lịch sử tin nhắn lưu vĩnh viễn theo booking/conversation
- Trạng thái: đã đọc / chưa đọc, typing indicator

### 12.2 Scheduled Messages (Host)
- Host tạo template tin nhắn tự động gắn với trigger:

| Trigger | Nội dung gợi ý |
|---|---|
| Booking confirmed | Chào mừng + xác nhận thông tin |
| 1 ngày trước check-in | Hướng dẫn đường đi, bản đồ GPS |
| Ngày check-in | Quy tắc tại khu, liên hệ khi cần |
| Ngày check-out | Cảm ơn + nhắc nhở dọn dẹp |

### 12.3 Broadcast (Host → All current guests)
- Host nhắn tin cho tất cả khách đang ở tại property
- Dùng cho: cảnh báo thời tiết, thay đổi quy tắc, thông báo khẩn

### 12.4 Rate Limits & Giới hạn

| Giới hạn | Giá trị | Lý do |
|---|---|---|
| Tin nhắn tối đa / phút / user | 30 tin | Chống spam |
| Ảnh: dung lượng tối đa | 10 MB / ảnh | Kiểm soát storage |
| Ảnh: định dạng cho phép | JPG, PNG, WEBP | Tránh file độc hại |
| Số ảnh / tin nhắn | Tối đa 5 ảnh | UX hợp lý |
| Broadcast tối đa / property / ngày | 3 lần | Chống Host spam khách |
| Scheduled message templates / site | Tối đa 10 templates | Giới hạn hợp lý |

---

## Module 13: Đánh giá & Review (2 chiều)

### 13.1 Camper review Host/Campsite
- Sau check-out, Camper có 14 ngày để viết review
- **Rating tổng thể:** 1–5 sao
- **Rating chi tiết (sub-categories):** Sạch sẽ, Vị trí, Tiện nghi, Giao tiếp, Giá trị
- Comment text (có giới hạn ký tự)
- Upload ảnh/video từ chuyến đi
- Host có thể viết **public reply** phản hồi review

### 13.2 Host review Camper
- Host đánh giá: Sạch sẽ, Tôn trọng quy tắc, Giao tiếp
- Rating 1–5 sao + comment
- **Blind review:** Review ẩn cho đến khi cả 2 bên hoàn thành (hoặc hết 14 ngày) để tránh ảnh hưởng lẫn nhau

### 13.3 Nhắc nhở viết review (Review Reminder)
- **Ngày 1 sau check-out:** Thông báo mời viết review (In-app + Push)
- **Ngày 7:** Nhắc nhở lần 2 nếu chưa viết (Email + Push)
- **Ngày 12:** Nhắc nhở lần cuối — "Còn 2 ngày để chia sẻ trải nghiệm" (Email + Push)
- **Ngày 14:** Đóng cửa sổ review — không nhắc nữa
- Áp dụng cho cả Camper và Host (blind review — nhắc độc lập)

### 13.4 Quản lý review
- User có thể report review không phù hợp
- Điểm rating ảnh hưởng trực tiếp đến ranking trên search

> **Admin actions:** Xem danh sách report review. Ẩn / xoá review vi phạm community standards.

---

## Module 14: Thông báo (Notifications)

### 14.1 Kênh thông báo
- **Email** (transactional)
- **Push notification** (mobile app — iOS & Android)
- **In-app notification** (bell icon — web & app)
- User tự cấu hình: bật/tắt từng loại thông báo theo từng kênh

**Default setting khi đăng ký mới:**

| Loại thông báo | Email | Push | In-app | Có thể tắt? |
|---|---|---|---|---|
| Transactional (booking, payment) | ✅ ON | ✅ ON | ✅ ON | ❌ Bắt buộc |
| Reminders (check-in, check-out) | ✅ ON | ✅ ON | ✅ ON | ✅ Tắt được |
| Tin nhắn mới | ✅ ON | ✅ ON | ✅ ON | ✅ Tắt được |
| Availability alerts | ✅ ON | ✅ ON | ✅ ON | ✅ Tắt được |
| Marketing / Khuyến mãi | ❌ OFF | ❌ OFF | ✅ ON | ✅ Tắt được |
| Cảnh báo thời tiết | ✅ ON | ✅ ON | ✅ ON | ✅ Tắt được |

- Marketing email: opt-in (không bật mặc định, tuân thủ quy định spam)
- Transactional notifications (booking confirmed, payment, cancellation) **không thể tắt** để đảm bảo user luôn nhận được thông tin quan trọng

### 14.2 Danh sách sự kiện thông báo

| Sự kiện | Camper | Host |
|---|---|---|
| Booking mới / Request mới | ✅ | ✅ |
| Booking confirmed | ✅ | ✅ |
| Booking declined | ✅ | |
| Booking cancelled | ✅ | ✅ |
| Nhắc check-in (1 ngày trước) | ✅ | ✅ |
| Nhắc check-out | ✅ | |
| Tin nhắn mới | ✅ | ✅ |
| Review mới nhận | | ✅ |
| Payout đã chuyển | | ✅ |
| Chỗ trống alert (availability alert) | ✅ | |
| Listing approved / rejected | | ✅ |
| Cảnh báo thời tiết xấu | ✅ | ✅ |

---

## Module 15: Wishlist & Yêu thích

- Camper lưu campsite vào danh sách yêu thích (heart button)
- Tạo và đặt tên nhiều collection: "Biển mùa hè", "Núi cuối tuần"...
- Chia sẻ wishlist collection với bạn bè qua link public

---

## Module 16: Mã giảm giá & Khuyến mãi

### 16.1 Host Discount Codes
- Host tạo mã giảm giá riêng cho property của mình
- Loại: giảm theo % hoặc số tiền cố định (VND)
- Điều kiện áp dụng: min số đêm, min giá trị booking
- Thời hạn sử dụng, giới hạn số lượt dùng

### 16.2 Platform Promotions (Admin quản lý)
- Admin tạo khuyến mãi toàn platform: giảm service fee, voucher cho user mới đăng ký
- Flash sale theo mùa (Tết, hè, lễ 30/4...)
- Mã giảm giá hệ thống có thể kết hợp với mã Host hoặc không (cấu hình)

### 16.3 Quy tắc áp dụng đồng thời (Discount Stacking)

| Tình huống | Cách tính |
|---|---|
| Mã Host + Platform Promotion (được phép kết hợp) | Áp mã Host trước → áp Platform Promotion trên subtotal sau khi đã giảm |
| Mã Host + Platform Promotion (không cho kết hợp) | Hệ thống chỉ áp mã có lợi hơn cho Camper, hiển thị lý do |
| Giảm dài ngày (long-stay) + mã Host | Cộng gộp — tính trên giá cơ bản |
| Giảm dài ngày + Platform Promotion | Áp giảm dài ngày trước → Platform Promotion trên subtotal |

- Giảm tối đa trên giá niêm yết (không gồm service fee): **60%** — Admin cấu hình ngưỡng này
- Service fee luôn tính trên giá **sau giảm**
- Breakdown hiển thị rõ thứ tự áp từng loại giảm giá cho Camper

---



## Module 17: Admin Panel

> Admin actions chi tiết cho từng nghiệp vụ đã được ghi rõ trong phần **Admin actions** của từng module tương ứng (Module 2, 3, 4, 5, 8, 9, 11, 13). Module này định nghĩa **giao diện tổng hợp** và **cấu hình nền tảng**.

### 17.1 Dashboard thống kê
- Tổng booking, doanh thu, user mới, listing mới — theo ngày/tuần/tháng/năm
- Biểu đồ xu hướng booking & doanh thu
- Top campsite (doanh thu / số booking), top Host
- Tỷ lệ huỷ, giá trị booking trung bình (AOV)
- Map heatmap: phân bố booking theo vùng địa lý

### 17.2 Hàng đợi xử lý (Moderation Queue)
- KYC cấp 2 & cấp 3 chờ duyệt
- Listing chờ duyệt (submit lần đầu)
- Report từ user (review vi phạm, listing vi phạm, user bị report)
- Tranh chấp booking chờ xử lý

### 17.3 Chính sách kiểm duyệt nội dung (Content Moderation Policy)

**Listing vi phạm (Approve / Reject khi duyệt, hoặc xoá sau khi live):**

| Loại vi phạm | Xử lý |
|---|---|
| Ảnh không phải thực tế (ảnh minh hoạ, ảnh fake) | Reject, yêu cầu thay ảnh |
| Mô tả sai sự thật, phóng đại nghiêm trọng | Reject / ẩn listing, cảnh báo Host |
| Giá ẩn / phí bất ngờ không khai báo | Yêu cầu bổ sung, re-review |
| Nội dung vi phạm pháp luật VN | Xoá ngay, báo cáo cơ quan có thẩm quyền nếu cần |

**Review vi phạm:**

| Loại vi phạm | Xử lý |
|---|---|
| Spam / nội dung quảng cáo | Xoá ngay |
| Hate speech, phân biệt đối xử | Xoá ngay + cảnh báo tài khoản |
| Review fake (không ở thực tế) | Xoá sau khi xác minh |
| Tiết lộ thông tin cá nhân người khác | Xoá ngay |

**User vi phạm:**

| Hành vi | Xử lý |
|---|---|
| Giả mạo danh tính | Suspend ngay, yêu cầu xác minh lại |
| Lừa đảo / scam | Ban vĩnh viễn |
| Quấy rối người dùng khác | Cảnh báo → Suspend → Ban |
| Vi phạm tài sản Host (kết luận qua Dispute) | Suspend, có thể ban |

### 17.4 Cấu hình nền tảng
- % service fee và % commission (theo loại chỗ ở nếu cần)
- Thời gian escrow release (số ngày sau check-in)
- Payout schedule (hàng tuần / 2 tuần)
- Danh mục hệ thống: tiện nghi, loại chỗ ở, hoạt động, đặc điểm tự nhiên

### 17.5 Quản lý người dùng
- Danh sách user (Camper/Host) — tìm kiếm, lọc theo status/role/ngày tạo
- Xem chi tiết: profile, booking history, review history, payout history
- Hành động: Ban / Suspend / Reactivate account
- Reset password, gửi email xác minh lại

### 17.6 Quản lý nội dung marketing
- Quản lý banner/hero section homepage
- Featured listings: chọn campsite hiển thị nổi bật
- Collections theo chủ đề: "Camping ven biển VN", "Top 10 Đà Lạt"
- Blog/Journal (bài viết về camping — nếu mở rộng sau)

---

## Module 18: Host Dashboard & Quản lý vận hành (Host)

> Khác Admin Panel (Module 18 — quản trị toàn platform), Host Dashboard là **giao diện kinh doanh cá nhân** của từng Host, chỉ hiển thị dữ liệu thuộc property/site của họ.

### 18.1 Tổng quan kinh doanh (Business Overview)
- Doanh thu: tháng này / tháng trước / tuỳ chọn khoảng thời gian
- Số booking: confirmed / completed / cancelled trong kỳ
- Occupancy rate (tỷ lệ lấp đầy) theo property và theo từng site
- Rating trung bình toàn property + số review mới chưa đọc
- So sánh với kỳ trước: tăng / giảm % (doanh thu, booking, rating)

### 18.2 Quản lý thu nhập (Earnings)
- Số dư đang trong escrow (chưa release)
- Tổng đã nhận (lịch sử payout)
- Breakdown doanh thu: site booking / add-on experiences / equipment rental
- Commission bị trừ từng kỳ
- Lịch payout tiếp theo (ngày dự kiến)
- Download báo cáo doanh thu (CSV / PDF) theo khoảng thời gian

### 18.3 Hiệu suất Listing (Listing Performance)
- Lượt xem listing (view count) theo ngày / tuần / tháng
- Tỷ lệ chuyển đổi: view → booking (conversion rate)
- Vị trí listing trên search result (thứ hạng trung bình)
- Tiến độ đạt Superhost: hiển thị % so với từng tiêu chí (Module 2.3)

### 18.4 Quản lý đánh giá (Review Management)
- Danh sách review nhận được (mới nhất trước)
- Rating breakdown tổng thể + từng sub-category (Sạch sẽ, Vị trí, Tiện nghi, Giao tiếp, Giá trị)
- Viết public reply cho review trực tiếp từ dashboard
- Flag review để request Admin xem xét (vi phạm community standards)
- Danh sách review của Host đã viết cho Camper (blind — ẩn đến khi publish)

### 18.5 Cài đặt vận hành nhanh (Quick Settings)
- Bật / tắt Instant Book per site trực tiếp từ dashboard
- Tạm dừng nhận booking toàn property (pause mode) với lý do
- Xem và chỉnh sửa nhanh giá hôm nay / tuần này trực tiếp từ dashboard
- Cảnh báo khi có Request to Book chưa phản hồi sắp timeout

---

## Luồng nghiệp vụ chính (Happy Path)

### Luồng Camper đặt chỗ (Instant Book)
```
1. Tìm kiếm theo địa điểm + ngày + số khách
2. Browse kết quả (list/map view), áp dụng filter
3. Xem chi tiết campsite (ảnh, mô tả, tiện nghi, review, giá)
4. Chọn ngày check-in/check-out
5. Thêm add-on (trải nghiệm / dụng cụ) nếu muốn
6. Xem breakdown tổng tiền
7. Điền thông tin & nhập mã giảm giá (nếu có)
8. Thanh toán
9. Nhận xác nhận booking + hướng dẫn
10. Check-in → Check-out → Viết review
```

### Luồng Host đăng listing
```
1. Đăng ký tài khoản
2. Bật vai trò Host → Xác minh eKYC (CMND/CCCD + SĐT)
3. Tạo Property (địa chỉ, mô tả, ảnh)
4. Tạo Site(s): loại, tiện nghi, ảnh, sức chứa
5. Thiết lập giá (base, weekend, holiday) + quy tắc
6. Thiết lập calendar (block dates, sync iCal)
7. Chọn booking mode (Instant / Request) per site
8. Chọn chính sách huỷ (Flexible/Moderate/Strict)
9. Submit → Admin review → Approved → Go live
10. Nhận booking → Giao tiếp với khách → Nhận payout
```

---

## Ghi chú mở rộng (Future Features)

> Các tính năng này **không thuộc phạm vi MVP/v1.0**, ghi nhận để phát triển về sau:

- **Roadtrip sharing:** Chia sẻ lịch trình chuyến đi với cộng đồng
- **Referral program:** Giới thiệu bạn bè nhận credit
- **Loyalty program:** Tích điểm đổi ưu đãi
- **API tích hợp thời tiết:** Cảnh báo mưa/bão cho booking sắp tới
- **Group/Event booking:** Đặt số lượng lớn cho team building, sự kiện
- **Multi-language:** Tiếng Anh cho thị trường quốc tế
- **Multi-currency:** USD, THB... khi mở rộng Đông Nam Á
- **Blog/Journal:** Nội dung cộng đồng về cắm trại VN
- **Gift cards:** Mua thẻ quà tặng Hipcamp-style

---

*Document này là Business Plan, chưa bao gồm quyết định kỹ thuật. Bước tiếp theo: Technical & Dev Plan.*
