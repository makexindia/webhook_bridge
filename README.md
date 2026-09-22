# Production-Grade MCP Webhook Bridge

A hardened, zero-dependency **Model Context Protocol (MCP)** Webhook Bridge built on **Next.js 15 (App Router)** and **TypeScript**, engineered for **Vercel** serverless deployment and optimized for **Gemini Spark**, **Claude Desktop**, and **Cursor**.

The service exposes a stateless Streamable HTTP MCP server hosting the `dispatch_webhook` tool. It provides native SSRF prevention, mandatory domain allowlisting, canonical HMAC-SHA256 signature generation, timing-safe authentication, and memory-safe response streaming.

---

## Key Security & Architectural Features

1. **Gemini Spark Auth & Anti-DCR Trap Guard**:
   - Supports authentication via both `Authorization: Bearer <token>` and `?token=<token>` (mandatory for Gemini Spark URL-based connection).
   - Both tokens are hashed with SHA-256 before invoking `crypto.timingSafeEqual`, preventing timing attacks and buffer-length `RangeError` crashes.
   - Rejects token conflicts: If both Bearer header and query param are supplied with conflicting values, it immediately aborts with HTTP 401.
   - **Anti-DCR**: Returns a bare JSON 401 `{ "error": "Unauthorized" }` with **no** `WWW-Authenticate` header and no OAuth metadata discovery routes (`/.well-known/oauth-protected-resource`). This prevents Gemini Spark from getting stuck in Dynamic Client Registration (DCR) traps and ensures it falls back to the token input prompt.

2. **SSRF Defense & Domain Allowlist**:
   - Webhook destinations must use the **HTTPS** protocol.
   - Hostnames are validated against `ALLOWED_WEBHOOK_DOMAINS` (mandatory in production; unconfigured environments will throw an initialization error).
   - Strict subdomain matching prevents domain suffix collision attacks (`api.makex.in` is allowed, while `evilmakex.in` is rejected).
   - Hostnames are resolved via `dns.promises.lookup` and all returned IPs are checked against private, loopback, link-local, and cloud metadata IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `0.0.0.0/8`, `::1`, `fc00::/7`, `fe80::/10`).
   - Outbound fetch enforces `redirect: "error"` to block 3xx open-redirect SSRF bypasses.

3. **Canonical HMAC-SHA256 Signing**:
   - When `WEBHOOK_HMAC_SECRET` is set and `signHmac` is enabled, outgoing requests include:
     - `X-Timestamp`: Current UTC Unix epoch in milliseconds (`Date.now().toString()`).
     - `X-Signature-SHA256`: Hex digest of HMAC-SHA256 over the canonical string:
       ```
       ${timestamp}\n${method.toUpperCase()}\n${canonicalUrl}\n${sha256(rawBody)}
       ```
   - Receivers enforce a **5-minute replay prevention window** (`|currentTime - timestamp| <= 300_000 ms`).

4. **Memory-Safe Response Streaming**:
   - Does not buffer arbitrary response sizes via `response.text()`.
   - Consumes response streams using `response.body.getReader()` up to a strict hard cap of **2,048 bytes**.
   - As soon as the byte cap is reached, `await reader.cancel()` is invoked immediately to release serverless memory, marking `truncated: true`.
   - Decodes to UTF-8 using `TextDecoder` *only after* byte accumulation finishes to prevent multi-byte emoji/character corruption.
   - Limits recorded response headers to a maximum of 20 normalized keys.

---

## Tool Specification: `dispatch_webhook`

```json
{
  "name": "dispatch_webhook",
  "description": "Dispatches an HTTP GET or POST request to a target webhook URL with optional JSON payload and HMAC-SHA256 signature verification.",
  "parameters": {
    "url": "https://api.makex.in/v1/events",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer external_api_key",
      "X-Partner-ID": "12345"
    },
    "payload": {
      "event": "customer.created",
      "data": { "id": "cust_998", "tier": "gold" }
    },
    "signHmac": true,
    "timeoutMs": 10000
  }
}
```

### Parameter Reference

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `url` | `string` | **Yes** | — | Target HTTPS webhook URL (must match `ALLOWED_WEBHOOK_DOMAINS`). |
| `method` | `"GET" \| "POST"` | No | `"POST"` | HTTP method to dispatch. |
| `headers` | `Record<string, string>` | No | `{}` | Outbound HTTP headers. Forbidden headers (`host`, `content-length`, `connection`, `transfer-encoding`) are stripped. |
| `payload` | `Record<string, unknown>`| No | `undefined` | JSON payload object sent with POST requests. |
| `signHmac`| `boolean` | No | `true` (if secret set) | Whether to compute and attach `X-Signature-SHA256` and `X-Timestamp`. |
| `timeoutMs` | `number` | No | `10000` | Request timeout in milliseconds (min: 1,000 ms, max: 25,000 ms). |

---

## Environment Variables

Copy `.env.example` to `.env.local`:

```bash
cp .env.example .env.local
```

| Variable | Required | Purpose | Example |
| :--- | :--- | :--- | :--- |
| `AUTH_TOKEN` | **Yes** | Bearer/Query secret required by MCP clients to access the endpoint. | `sec_abc123...` |
| `WEBHOOK_HMAC_SECRET` | No | Secret key used to generate HMAC-SHA256 signatures for outgoing webhooks. | `hmac_key_987...` |
| `ALLOWED_WEBHOOK_DOMAINS` | **Yes (in prod)** | Comma-separated allowlist of valid target domains and subdomains. | `makex.in,api.stripe.com` |

---

## Connecting to MCP Clients

### 1. Gemini Spark
Gemini Spark connects directly to Streamable HTTP endpoints. Use the full URL with query parameter authentication:

```
https://your-bridge-domain.vercel.app/api/mcp?token=YOUR_AUTH_TOKEN
```

### 2. Claude Desktop (`claude_desktop_config.json`)

Using `mcp-remote`:

```json
{
  "mcpServers": {
    "webhook-bridge": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://your-bridge-domain.vercel.app/api/mcp",
        "--header",
        "Authorization: Bearer YOUR_AUTH_TOKEN"
      ]
    }
  }
}
```

### 3. Cursor (`mcp.json`)

```json
{
  "mcpServers": {
    "webhook-bridge": {
      "url": "https://your-bridge-domain.vercel.app/api/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_AUTH_TOKEN"
      }
    }
  }
}
```

---

## Receiver Verification Recipes (5-Minute Replay Window)

Webhook targets should verify signatures using the canonical message format:
```
${timestamp}\n${method.toUpperCase()}\n${canonicalUrl}\n${sha256(rawBody)}
```

### Node.js / Express Verification

```typescript
import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";

export function verifyWebhookSignature(secret: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const timestamp = req.header("X-Timestamp");
    const signature = req.header("X-Signature-SHA256");

    if (!timestamp || !signature) {
      return res.status(401).json({ error: "Missing signature headers" });
    }

    // 1. Enforce 5-minute replay prevention window
    const now = Date.now();
    const sentTime = Number.parseInt(timestamp, 10);
    if (Number.isNaN(sentTime) || Math.abs(now - sentTime) > 5 * 60 * 1000) {
      return res.status(401).json({ error: "Timestamp expired or outside 5-minute window" });
    }

    // 2. Compute raw body hash
    const rawBody = (req as any).rawBody || (req.body ? JSON.stringify(req.body) : "");
    const bodyHash = crypto.createHash("sha256").update(rawBody, "utf8").digest("hex");

    // 3. Reconstruct canonical URL (protocol + host + originalUrl)
    const canonicalUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;

    // 4. Construct canonical message
    const canonicalMessage = `${timestamp}\n${req.method.toUpperCase()}\n${canonicalUrl}\n${bodyHash}`;

    // 5. Compare signatures in constant time
    const expectedSig = crypto.createHmac("sha256", secret).update(canonicalMessage, "utf8").digest("hex");

    const sigBuf = Buffer.from(signature, "hex");
    const expBuf = Buffer.from(expectedSig, "hex");

    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return res.status(401).json({ error: "Invalid HMAC signature" });
    }

    next();
  };
}
```

### Python / FastAPI Verification

```python
import time
import hmac
import hashlib
from fastapi import Request, HTTPException, Security

WEBHOOK_SECRET = "your-webhook-signing-secret-here"

async def verify_webhook(request: Request):
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature-SHA256")

    if not timestamp or not signature:
        raise HTTPException(status_code=401, detail="Missing signature headers")

    # 1. Enforce 5-minute replay window (300,000 ms)
    now_ms = int(time.time() * 1000)
    try:
        sent_ms = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp format")

    if abs(now_ms - sent_ms) > 300000:
        raise HTTPException(status_code=401, detail="Timestamp outside 5-minute replay window")

    # 2. Hash raw body
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()

    # 3. Canonical string
    canonical_url = str(request.url)
    canonical_message = f"{timestamp}\n{request.method.upper()}\n{canonical_url}\n{body_hash}"

    # 4. HMAC-SHA256 comparison
    expected_sig = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        canonical_message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")
```

---

## Deployment to Vercel

1. Push your repository to GitHub.
2. Import the repository into [Vercel](https://vercel.com).
3. Under **Settings > Environment Variables**, add:
   - `AUTH_TOKEN` = `your-secure-mcp-client-token`
   - `WEBHOOK_HMAC_SECRET` = `your-webhook-hmac-secret`
   - `ALLOWED_WEBHOOK_DOMAINS` = `makex.in,api.makex.in,your-api-domain.com`
4. Deploy. The MCP route will be live at `https://your-deployment.vercel.app/api/mcp`.

### Cloudflare CNAME Setup
If placing a custom domain behind Cloudflare:
- Add a `CNAME` record pointing to `cname.vercel-dns.com`.
- Ensure SSL/TLS encryption mode is set to **Full (strict)**.

---

## Development & Testing

```bash
# 1. Install dependencies
npm install

# 2. Run TypeScript typecheck
npm run type-check

# 3. Run ESLint
npm run lint

# 4. Run Vitest test suites
npm run test
```
