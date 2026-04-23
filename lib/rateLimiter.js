/**
 * In-memory sliding-window rate limiter.
 *
 * Each instance tracks requests per IP within a configurable window.
 * Suitable for single-process deployments. For multi-instance
 * deployments, swap this for a Redis-backed implementation.
 */

/**
 * Creates a rate limiter with the given configuration.
 *
 * @param {object} options
 * @param {number} options.maxRequests — Maximum requests allowed within the window
 * @param {number} options.windowMs    — Window duration in milliseconds
 * @returns {{ check: (request: Request) => { allowed: boolean, remaining: number, retryAfterMs?: number } }}
 */
export function createRateLimiter({ maxRequests = 5, windowMs = 60_000 } = {}) {
  /** @type {Map<string, number[]>} IP → array of timestamps */
  const store = new Map();

  // Periodically clean up expired entries to prevent memory leaks
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of store.entries()) {
      const valid = timestamps.filter((t) => now - t < windowMs);
      if (valid.length === 0) {
        store.delete(ip);
      } else {
        store.set(ip, valid);
      }
    }
  }, windowMs * 2);

  // Allow the process to exit without waiting for the interval
  if (cleanupInterval.unref) {
    cleanupInterval.unref();
  }

  return {
    /**
     * Check whether a request from the given IP is allowed.
     *
     * @param {Request} request
     * @returns {{ allowed: boolean, remaining: number, retryAfterMs?: number }}
     */
    check(request) {
      const ip = getClientIp(request);
      const now = Date.now();

      // Get existing timestamps for this IP, filtered to the current window
      const timestamps = (store.get(ip) || []).filter(
        (t) => now - t < windowMs
      );

      if (timestamps.length >= maxRequests) {
        // Oldest timestamp in the window determines when the client can retry
        const oldestInWindow = timestamps[0];
        const retryAfterMs = windowMs - (now - oldestInWindow);

        return {
          allowed: false,
          remaining: 0,
          retryAfterMs,
        };
      }

      // Record this request
      timestamps.push(now);
      store.set(ip, timestamps);

      return {
        allowed: true,
        remaining: maxRequests - timestamps.length,
      };
    },
  };
}

/**
 * Extracts the client IP from the request.
 * Checks x-forwarded-for first (for reverse proxies), then falls back.
 *
 * @param {Request} request
 * @returns {string}
 */
function getClientIp(request) {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    // x-forwarded-for may contain multiple IPs; the first is the client
    return forwarded.split(",")[0].trim();
  }

  const realIp = request.headers.get("x-real-ip");
  if (realIp) {
    return realIp.trim();
  }

  return "unknown";
}
