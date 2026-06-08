/**
 * Strips HTML tags from a string to prevent stored XSS.
 * @param {string} val
 * @returns {string}
 */
export function stripHtml(val) {
  if (typeof val !== 'string') return val;
  return val.replace(/<[^>]*>/g, '').trim();
}

/**
 * Sanitizes a value for safe inclusion in a CSV cell.
 * Neutralizes CSV injection by prefixing dangerous leading characters.
 * @param {string|number|boolean|null|undefined} val
 * @returns {string}
 */
export function sanitizeCsvCell(val) {
  if (val === null || val === undefined) return '';
  const str = String(val);
  // Neutralize formula injection: Excel/Sheets execute cells starting with = + - @ \t \r
  if (/^[=+\-@\t\r]/.test(str)) {
    return `'${str}`;
  }
  // Wrap in quotes if contains comma, quote, or newline
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Sanitizes a plain text input field:
 * - Strips HTML
 * - Trims whitespace
 * - Returns null if empty
 * @param {string} val
 * @returns {string|null}
 */
export function sanitizeTextField(val) {
  if (typeof val !== 'string') return null;
  const clean = stripHtml(val).trim();
  return clean.length > 0 ? clean : null;
}

/**
 * Neutralizes spreadsheet formula injection in a stored string.
 * Prefixes the value with a single apostrophe when the first character is
 * one of the characters Excel/Sheets treat as formula sigils (= + - @ TAB CR).
 * Safe to apply before DB inserts — unlike sanitizeCsvCell it does not add
 * CSV quoting, so the stored value remains human-readable.
 * @param {string|null} val
 * @returns {string|null}
 */
export function neutralizeFormula(val) {
  if (typeof val !== 'string') return val;
  if (/^[=+\-@\t\r]/.test(val)) return `'${val}`;
  return val;
}

/**
 * Sanitizes a string for safe inclusion in API error messages.
 * Strips HTML tags and limits length to prevent error message injection.
 * @param {string} val
 * @param {number} maxLength
 * @returns {string}
 */
export function sanitizeErrorMessage(val, maxLength = 200) {
  if (typeof val !== 'string') return 'Unknown error';
  return val.replace(/<[^>]*>/g, '').trim().slice(0, maxLength);
}
