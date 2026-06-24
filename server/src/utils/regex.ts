/**
 * Utility: Escape special regex characters từ user input
 * Ngăn chặn ReDoS (Regex Denial of Service) attack
 * 
 * Ví dụ: "(a+)+" input sẽ bị escape thành "\(a\+\)\+"
 * → không thể gây catastrophic backtracking trong MongoDB regex
 */
export function escapeRegex(input: string): string {
  // Escape tất cả ký tự đặc biệt trong regex
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Tạo MongoDB-safe regex từ user search input
 * @param search - Raw user input
 * @param maxLength - Giới hạn độ dài tối đa (default 100)
 */
export function buildSafeSearchRegex(search: string, maxLength = 100): RegExp {
  const trimmed = search.trim().slice(0, maxLength);
  const escaped = escapeRegex(trimmed);
  return new RegExp(escaped, "i");
}
