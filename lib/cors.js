/**
 * Shared CORS headers for all API responses.
 * Import and spread these into any Response or NextResponse headers.
 */
export const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json',
};

/**
 * Returns a 204 No Content preflight response with CORS headers.
 * Re-export this as `OPTIONS` in every route file that needs CORS.
 */
export function handleCORSPreflight() {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

/**
 * Wraps a JSON payload in a Response with CORS headers included.
 *
 * @param {object} body  - The JSON-serialisable response body
 * @param {number} status - HTTP status code
 */
export function corsResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: CORS_HEADERS,
  });
}
