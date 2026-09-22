import crypto from "node:crypto";

export interface AuthValidationResult {
  authorized: boolean;
  reason?: string;
}

/**
 * Validates authentication tokens from Bearer header and/or ?token= query parameter.
 * Uses SHA-256 pre-hashing before timingSafeEqual to avoid timing leaks and buffer RangeErrors.
 * If both tokens are supplied with mismatched values, returns 401 immediately.
 */
export function validateAuth(request: Request): AuthValidationResult {
  const expectedToken = process.env.AUTH_TOKEN;
  if (!expectedToken) {
    return { authorized: false, reason: "Server AUTH_TOKEN is not configured." };
  }

  // 1. Extract Bearer token
  let bearerToken: string | null = null;
  const authHeader = request.headers.get("authorization");
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match) {
      bearerToken = match[1].trim();
    }
  }

  // 2. Extract query param token
  let queryToken: string | null = null;
  try {
    const url = new URL(request.url);
    queryToken = url.searchParams.get("token");
  } catch {
    // ignore
  }

  // Conflict handling: If both are supplied and mismatch, immediately return unauthorized
  if (bearerToken !== null && queryToken !== null && bearerToken !== queryToken) {
    return {
      authorized: false,
      reason: "Credential mismatch between Bearer header and query param.",
    };
  }

  const candidate = bearerToken ?? queryToken;
  if (!candidate) {
    return { authorized: false, reason: "Missing authentication token." };
  }

  // Pre-hash candidate and secret with SHA-256 to ensure identical 32-byte buffers
  const candidateHash = crypto.createHash("sha256").update(candidate, "utf8").digest();
  const expectedHash = crypto.createHash("sha256").update(expectedToken, "utf8").digest();

  if (crypto.timingSafeEqual(candidateHash, expectedHash)) {
    return { authorized: true };
  }

  return { authorized: false, reason: "Invalid authentication token." };
}

/**
 * Creates bare JSON 401 response without WWW-Authenticate header
 * to prevent Gemini Spark DCR (Dynamic Client Registration) traps.
 */
export function createUnauthorizedResponse(): Response {
  return new Response(JSON.stringify({ error: "Unauthorized" }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
    },
  });
}
