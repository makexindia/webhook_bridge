import crypto from "node:crypto";
import dns from "node:dns/promises";
import { z } from "zod";

/**
 * Raw Zod shape for the `dispatch_webhook` tool.
 */
export const webhookInputShape = {
  url: z
    .string()
    .url("Invalid URL format")
    .describe("Target webhook URL (HTTPS only)"),
  method: z
    .enum(["GET", "POST"])
    .default("POST")
    .describe("HTTP method to use (GET or POST, default: POST)"),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Optional HTTP headers to send (dangerous headers are stripped)"),
  payload: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Optional JSON payload object (for POST requests)"),
  signHmac: z
    .boolean()
    .optional()
    .describe("Whether to attach canonical HMAC-SHA256 signature (default: true if secret is set)"),
  timeoutMs: z
    .number()
    .int("Timeout must be an integer")
    .min(1000, "Minimum timeout is 1000ms")
    .max(25000, "Maximum timeout is 25000ms")
    .default(10000)
    .describe("Request timeout in milliseconds (min: 1000, max: 25000, default: 10000)"),
};

/**
 * Zod input schema for the `dispatch_webhook` tool.
 */
export const webhookInputSchema = z.object(webhookInputShape);

export type WebhookInput = z.infer<typeof webhookInputSchema>;

export interface WebhookExecutionResult {
  success: boolean;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: string;
  truncated?: boolean;
  error?: string;
}

/**
 * Forbidden headers that must be stripped from outbound requests.
 */
const FORBIDDEN_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "transfer-encoding",
]);

/**
 * Validates whether an IPv4 address falls within restricted/private/loopback ranges.
 */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((n) => Number.parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return false;
  }

  const [p0, p1] = parts;

  // 0.0.0.0/8 (Current network)
  if (p0 === 0) return true;

  // 10.0.0.0/8 (Private network)
  if (p0 === 10) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (p0 === 127) return true;

  // 169.254.0.0/16 (Link-local / Cloud metadata)
  if (p0 === 169 && p1 === 254) return true;

  // 172.16.0.0/12 (Private network: 172.16.0.0 - 172.31.255.255)
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;

  // 192.168.0.0/16 (Private network)
  if (p0 === 192 && p1 === 168) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (p0 >= 224) return true;

  return false;
}

/**
 * Validates whether an IPv6 address falls within restricted/private/loopback ranges.
 */
export function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith("::ffff:")) {
    const v4Part = normalized.slice(7);
    if (v4Part.includes(".")) {
      return isPrivateIPv4(v4Part);
    }
  }

  // Loopback (::1)
  if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") {
    return true;
  }

  // Unspecified (::)
  if (normalized === "::" || normalized === "0:0:0:0:0:0:0:0") {
    return true;
  }

  // Unique Local Address (fc00::/7 -> fc00... to fdff...)
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }

  // Link-Local (fe80::/10 -> fe8, fe9, fea, feb)
  if (
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb")
  ) {
    return true;
  }

  return false;
}

/**
 * Checks if an IP string (v4 or v6) is private or internal.
 */
export function isPrivateIP(ip: string): boolean {
  return isPrivateIPv4(ip) || isPrivateIPv6(ip);
}

/**
 * Parses and retrieves the allowed domains list from environment.
 * Throws in production if unconfigured.
 */
export function getAllowedDomains(): string[] {
  const raw = process.env.ALLOWED_WEBHOOK_DOMAINS;
  const isProduction = process.env.NODE_ENV === "production";

  if (!raw || raw.trim() === "") {
    if (isProduction) {
      throw new Error(
        "SSRF Guard Configuration Error: ALLOWED_WEBHOOK_DOMAINS is mandatory in production but was not configured."
      );
    }
    return [];
  }

  return raw
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Validates that the hostname matches an allowed domain or exact subdomain.
 */
export function isHostnameAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) {
    // If not configured (only permitted in non-production), allow any public domain
    return true;
  }

  const normalized = hostname.toLowerCase();
  return allowedDomains.some(
    (domain) => normalized === domain || normalized.endsWith("." + domain)
  );
}

export interface WebhookValidationOptions {
  dnsLookup?: (hostname: string, options: { all: true }) => Promise<Array<{ address: string; family: number }>>;
}

/**
 * Validates a target webhook URL for HTTPS, allowed domains, and safe public IP resolution.
 */
export async function validateWebhookUrl(
  urlStr: string,
  options?: WebhookValidationOptions
): Promise<URL> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlStr);
  } catch {
    throw new Error("Invalid URL format.");
  }

  // 1. Enforce HTTPS only
  if (parsedUrl.protocol !== "https:") {
    throw new Error("Invalid URL scheme: Only HTTPS webhooks are permitted.");
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // 2. Reject obvious loopback/local names
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "0.0.0.0") {
    throw new Error(`SSRF Guard: Target host '${hostname}' is a forbidden loopback address.`);
  }

  // Check direct IP address in hostname
  if (isPrivateIP(hostname)) {
    throw new Error(`SSRF Guard: Target host '${hostname}' is a restricted private IP.`);
  }

  // 3. Domain allowlist check
  const allowedDomains = getAllowedDomains();
  if (!isHostnameAllowed(hostname, allowedDomains)) {
    throw new Error(
      `SSRF Guard: Domain '${hostname}' is not in ALLOWED_WEBHOOK_DOMAINS (${allowedDomains.join(", ")}).`
    );
  }

  // 4. DNS resolution and IP verification
  let records: Array<{ address: string; family: number }>;
  try {
    const res = options?.dnsLookup
      ? await options.dnsLookup(hostname, { all: true })
      : await dns.lookup(hostname, { all: true });
    records = Array.isArray(res) ? res : [res];
  } catch (err) {
    throw new Error(`DNS Resolution failed for host '${hostname}': ${(err as Error).message}`);
  }

  if (!records || records.length === 0) {
    throw new Error(`DNS Resolution yielded no IP addresses for host '${hostname}'.`);
  }

  for (const record of records) {
    if (isPrivateIP(record.address)) {
      throw new Error(
        `SSRF Guard: Host '${hostname}' resolved to restricted IP '${record.address}'. Outbound request aborted.`
      );
    }
  }

  return parsedUrl;
}

/**
 * Sanitizes headers by stripping forbidden / dangerous headers and downcasing keys.
 */
export function sanitizeOutboundHeaders(
  customHeaders?: Record<string, string | unknown>
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  if (!customHeaders) return sanitized;

  for (const [key, value] of Object.entries(customHeaders)) {
    const lowerKey = key.toLowerCase();
    if (!FORBIDDEN_HEADERS.has(lowerKey) && value !== undefined && value !== null) {
      sanitized[key] = String(value);
    }
  }

  return sanitized;
}

/**
 * Computes canonical HMAC-SHA256 signature according to specification:
 * Canonical String: `${timestamp}\n${method.toUpperCase()}\n${canonicalUrl}\n${sha256(rawBody)}`
 */
export function computeCanonicalHmacSignature(params: {
  timestamp: string;
  method: string;
  canonicalUrl: string;
  serializedBody: string;
  secret: string;
}): { signature: string; bodyHash: string } {
  const bodyHash = crypto
    .createHash("sha256")
    .update(params.serializedBody, "utf8")
    .digest("hex");

  const canonicalMessage = `${params.timestamp}\n${params.method.toUpperCase()}\n${params.canonicalUrl}\n${bodyHash}`;

  const signature = crypto
    .createHmac("sha256", params.secret)
    .update(canonicalMessage, "utf8")
    .digest("hex");

  return { signature, bodyHash };
}

export interface DispatchWebhookOptions extends WebhookValidationOptions {
  customFetch?: typeof fetch;
  hmacSecret?: string;
}

/**
 * Reads response body via ReadableStreamDefaultReader up to 2,048 bytes max.
 * Decodes to UTF-8 only after accumulation finishes.
 */
export async function readStreamWithLimit(
  bodyStream: ReadableStream<Uint8Array> | null,
  limitBytes = 2048
): Promise<{ text: string; truncated: boolean }> {
  if (!bodyStream) {
    return { text: "", truncated: false };
  }

  const reader = bodyStream.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      if (value) {
        if (totalBytes + value.byteLength >= limitBytes) {
          const needed = limitBytes - totalBytes;
          if (needed > 0) {
            chunks.push(value.subarray(0, needed));
            totalBytes += needed;
          }
          truncated = true;
          // Cancel reader immediately upon hitting hard cap
          await reader.cancel();
          break;
        } else {
          chunks.push(value);
          totalBytes += value.byteLength;
        }
      }
    }
  } catch (err) {
    // If stream reading fails or is aborted
    try {
      await reader.cancel();
    } catch {
      // ignore
    }
    throw err;
  }

  // Concatenate all accumulated Uint8Array chunks
  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  // Decode to UTF-8 post-accumulation to preserve multibyte character integrity
  const text = new TextDecoder("utf-8").decode(merged);
  return { text, truncated };
}

/**
 * Normalizes response headers and caps recorded keys to a maximum of 20.
 */
export function extractResponseHeaders(headers: Headers, maxKeys = 20): Record<string, string> {
  const result: Record<string, string> = {};
  let count = 0;

  headers.forEach((value, key) => {
    if (count < maxKeys) {
      result[key.toLowerCase()] = value;
      count++;
    }
  });

  return result;
}

/**
 * Dispatches an HTTP GET or POST request to target webhook URL.
 */
export async function dispatchWebhook(
  input: WebhookInput,
  options?: DispatchWebhookOptions
): Promise<WebhookExecutionResult> {
  try {
    // 1. Validate URL, scheme, domain allowlist, and resolved IP
    const parsedUrl = await validateWebhookUrl(input.url, options);

    // 2. Prepare outbound headers
    const outboundHeaders = sanitizeOutboundHeaders(input.headers);

    // 3. Serialize payload if POST
    let serializedBody = "";
    let requestBody: string | undefined = undefined;

    if (input.method === "POST" && input.payload !== undefined) {
      serializedBody = JSON.stringify(input.payload);
      requestBody = serializedBody;
      if (!outboundHeaders["content-type"]) {
        outboundHeaders["content-type"] = "application/json";
      }
    }

    // 4. Canonical HMAC-SHA256 signature if enabled and secret present
    const hmacSecret = options?.hmacSecret ?? process.env.WEBHOOK_HMAC_SECRET;
    const shouldSign = input.signHmac ?? Boolean(hmacSecret);

    if (shouldSign && hmacSecret) {
      const timestamp = Date.now().toString();
      const canonicalUrl = parsedUrl.toString();
      const { signature } = computeCanonicalHmacSignature({
        timestamp,
        method: input.method,
        canonicalUrl,
        serializedBody,
        secret: hmacSecret,
      });

      outboundHeaders["X-Timestamp"] = timestamp;
      outboundHeaders["X-Signature-SHA256"] = signature;
    }

    // 5. Outbound fetch execution with redirect: "error" and timeout signal
    const fetchFn = options?.customFetch ?? fetch;
    const response = await fetchFn(parsedUrl.toString(), {
      method: input.method,
      headers: outboundHeaders,
      body: requestBody,
      redirect: "error",
      signal: AbortSignal.timeout(input.timeoutMs),
    });

    // 6. Memory-safe stream consumption capped at 2,048 bytes
    const { text: body, truncated } = await readStreamWithLimit(response.body, 2048);

    // 7. Extract up to 20 normalized headers
    const recordedHeaders = extractResponseHeaders(response.headers, 20);

    return {
      success: response.ok,
      status: response.status,
      statusText: response.statusText,
      headers: recordedHeaders,
      body,
      truncated,
    };
  } catch (error) {
    return {
      success: false,
      error: (error as Error).message || "Unknown error during webhook dispatch.",
    };
  }
}
