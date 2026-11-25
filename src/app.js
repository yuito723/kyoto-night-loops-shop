/**
 * JP Business Register v1 — self-hosted x402 sales endpoint (Node / Render)
 *
 * Ported from the Cloudflare Workers version (../x402-shop/src/index.js).
 * The handler below is written against the web-standard fetch API
 * (Request/Response); server.js adapts Node's http server to it.
 *
 * Routes
 *   GET /                     free: product catalog (name, description, price, schema)
 *   GET /.well-known/x402     free: same catalog (x402 discovery convention)
 *   GET /sample               free: contents/license preview of the video pack
 *   GET /openapi.json         free: OpenAPI doc with x-payment-info (x402scan reads this)
 *   GET /healthz              free: 200 liveness probe (Render health check)
 *   GET /download             paid: x402 (exact, USDC on Base) -> ZIP from local file
 *
 * Protocol: x402 v2 on the wire (PAYMENT-REQUIRED / PAYMENT-SIGNATURE /
 * PAYMENT-RESPONSE headers, CAIP-2 network id), with x402 v1 payment payloads
 * (X-PAYMENT header, network "base") also accepted for older clients.
 * Facilitator: PayAI (https://facilitator.payai.network) POST /verify -> /settle.
 *
 * Spec references (verified 2026-11-24):
 *   - x402-foundation/x402 specs/x402-specification-v2.md (sections 5.1-5.4, 7.1-7.3)
 *   - PayAI facilitator OpenAPI: https://facilitator.payai.network/openapi.json
 *   - PayAI /supported: x402Version 2 "exact" on eip155:8453 is live.
 *
 * The ZIP is NEVER served from a public URL and is only delivered after the
 * facilitator has verified AND settled the payment. Dataset sources, in
 * priority order (first one that loads wins):
 *   1. DATASET_ZIP_PATH — plaintext ZIP file (local dev / Render Secret File
 *      at /etc/secrets/dataset.zip; Render Secret Files are plaintext-only
 *      and capped at 1 MB total, so this does not fit the 3.2 MB ZIP there).
 *   2. DATASET_ENC_PATH (default ./dataset.zip.enc) — AES-256-GCM encrypted
 *      ZIP, decrypted in memory with DATASET_KEY.
 *   3. DATASET_ENC_B64_DIR (default ./data) — the same ciphertext as base64
 *      text chunks (data/dataset.enc.b64.NNN), committed to the public git
 *      repository; decrypted in memory with DATASET_KEY. This is the source
 *      used in production on Render: the ciphertext is public, the key is
 *      only in the Render Dashboard environment.
 * DATASET_KEY is base64 of 32 random bytes and must NEVER be committed.
 */

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { createDecipheriv, scryptSync } from "node:crypto";

// ---------------------------------------------------------------------------
// Product / payment constants (single source of truth)
// ---------------------------------------------------------------------------

const PRODUCT = {
  name: "Japan Night Loops - Kyoto, Matsue Castle & Kurashiki (6 seamless loops, HD)",
  slug: "japan-night-loops-v2",
  version: "v2",
  license: "Commercial use allowed (streams, videos, signage). No resale or redistribution of the raw file.",
  attribution: "Source: MLIT PLATEAU (https://www.mlit.go.jp/plateau/), processed/edited. City model data: Kyoto City, Matsue City, Kurashiki City / MLIT, PDL 1.0 (CC BY 4.0 compatible).",
  format:
    "Encrypted ZIP (AES-256-GCM) containing six seamless loop MP4s (1664x960, 24fps, H.264) and six poster stills. The decryption key is delivered after payment.",
  zipFilename: "japan-night-loops.zip",
  shortDescription:
    "Six seamless night loops of Kyoto (Pontocho & Kamo River), Matsue Castle and Kurashiki Bikan, built from real PLATEAU 3D city data (Blender + Wan 2.2 AI video, Apache 2.0). 1664x960 HD. Key-after-payment delivery.",
  description:
    "Six seamless ambient night loops of famous Japanese scenes: (1) a forward dolly flight through a lantern-lit Pontocho canal street in Kyoto with drifting mist, (2) a lantern-lit canal scene with flowing water and shimmering reflections, (3) an aerial drone flight over the Kamo River at blue hour, (4) a blue-hour dusk view of the Kyoto riverside restaurant row, (5) the illuminated black keep of Matsue Castle above its moat, (6) white-walled storehouses and willows along the Kurashiki Bikan canal. Unlike purely text-prompted AI video, the base geometry is the real surveyed city: MLIT PLATEAU open 3D city data of Kyoto, Matsue and Kurashiki, rendered in Blender, then cinematized with the open-source Wan 2.2 video model (Apache 2.0) - AI-cinematized artistic renderings based on real city geometry, not photographs. Each loop is 12-16 seconds, 1664x960, 24fps, and loops seamlessly. Delivered as an encrypted ZIP; the decryption key is returned by this endpoint after x402 payment settles.",
  contactEmail: "yuito723@muse.ai",
};

// Column codebook (listing.md section 2)
const SCHEMA = [
  { column: "kyoto-pontocho-canal-dolly-loop.mp4", type: "MP4 (H.264)", description: "Seamless loop, 1664x960, 24fps, 16.2s - forward dolly through a lantern-lit canal street, mist and reflections" },
  { column: "kyoto-lantern-canal-loop.mp4", type: "MP4 (H.264)", description: "Seamless loop, 1664x960, 24fps, 12.1s - lantern-lit canal, flowing water and mist" },
  { column: "kyoto-kamo-river-drone-loop.mp4", type: "MP4 (H.264)", description: "Seamless loop, 1664x960, 24fps, 16.2s - aerial drone flight over the Kamo River at blue hour" },
  { column: "kyoto-riverside-dusk-loop.mp4", type: "MP4 (H.264)", description: "Seamless loop, 1664x960, 24fps, 13.5s - blue-hour riverside restaurant row" },
  { column: "matsue-castle-moat-loop.mp4", type: "MP4 (H.264)", description: "Seamless loop, 1664x960, 24fps, 16.2s - illuminated Matsue Castle keep above its moat, slow camera drift" },
  { column: "kurashiki-bikan-canal-loop.mp4", type: "MP4 (H.264)", description: "Seamless loop, 1664x960, 24fps, 16.2s - Kurashiki Bikan canal, white-walled storehouses and willows, slow camera drift" },
  { column: "poster-*.png (6 files)", type: "PNG", description: "Poster still frames, one per clip" },
  { column: "README.md", type: "Markdown", description: "Contents, production notes, PLATEAU attribution and license terms" },
];

// Payment terms — x402 "exact" scheme, USDC on Base mainnet.
// USDC contract on Base: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 (spec examples).
const PAYMENT = {
  scheme: "exact",
  networkV2: "eip155:8453", // CAIP-2 for Base mainnet (x402 v2)
  networkV1: "base", // x402 v1 network name for the same chain
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
  amountAtomic: "9000000", // $9.00 — USDC has 6 decimals
  priceUsd: "9.00",
  maxTimeoutSeconds: 300,
  // EIP-712 domain of USDC on Base, required in `extra` so clients can sign
  // the EIP-3009 authorization (x402 spec v1/v2 examples for Base USDC).
  extra: { name: "USD Coin", version: "2" },
};

const DEFAULT_FACILITATOR_URL = "https://facilitator.payai.network";
const DEFAULT_PAY_TO = "0x09Ca92BDba3da86B0253840285dbA66dce1A78D7";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function b64encodeJson(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decodeJson(str) {
  const bin = atob(str.trim());
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(bytes));
}

function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE",
      ...extraHeaders,
    },
  });
}

function config(env) {
  return {
    payTo: env.PAY_TO || DEFAULT_PAY_TO,
    facilitatorUrl: (env.FACILITATOR_URL || DEFAULT_FACILITATOR_URL).replace(/\/+$/, ""),
    facilitatorApiKey: env.FACILITATOR_API_KEY || null,
  };
}

function downloadUrl(request) {
  return `${new URL(request.url).origin}/download`;
}

/** x402 v2 PaymentRequirements for the /download resource. */
function requirementsV2(request, cfg) {
  return {
    scheme: PAYMENT.scheme,
    network: PAYMENT.networkV2,
    amount: PAYMENT.amountAtomic,
    asset: PAYMENT.asset,
    payTo: cfg.payTo,
    maxTimeoutSeconds: PAYMENT.maxTimeoutSeconds,
    extra: { ...PAYMENT.extra },
  };
}

/** x402 v1 PaymentRequirements (legacy field names) for the same resource. */
function requirementsV1(request, cfg) {
  return {
    scheme: PAYMENT.scheme,
    network: PAYMENT.networkV1,
    maxAmountRequired: PAYMENT.amountAtomic,
    resource: downloadUrl(request),
    description: PRODUCT.shortDescription,
    mimeType: "application/json",
    payTo: cfg.payTo,
    maxTimeoutSeconds: PAYMENT.maxTimeoutSeconds,
    asset: PAYMENT.asset,
    extra: { ...PAYMENT.extra },
  };
}

/** x402 v2 PaymentRequired object (spec section 5.1). */
function paymentRequiredV2(request, cfg, error) {
  return {
    x402Version: 2,
    error: error || "PAYMENT-SIGNATURE header is required",
    resource: {
      url: downloadUrl(request),
      description: PRODUCT.shortDescription,
      mimeType: "application/json",
    },
    accepts: [requirementsV2(request, cfg)],
  };
}

/** 402 response: v2 PaymentRequired in BOTH the PAYMENT-REQUIRED header and the JSON body. */
function paymentRequiredResponse(request, cfg, error) {
  const body = paymentRequiredV2(request, cfg, error);
  return jsonResponse(body, 402, {
    "PAYMENT-REQUIRED": b64encodeJson(body),
  });
}

// ---------------------------------------------------------------------------
// Catalog / sample / openapi (free routes)
// ---------------------------------------------------------------------------

function catalog(request, cfg) {
  const origin = new URL(request.url).origin;
  return {
    name: PRODUCT.name,
    slug: PRODUCT.slug,
    version: PRODUCT.version,
    description: PRODUCT.description,
    format: PRODUCT.format,
    license: PRODUCT.license,
    attribution: PRODUCT.attribution,
    attribution: PRODUCT.attribution,
    price: {
      amount_usd: PAYMENT.priceUsd,
      amount_atomic: PAYMENT.amountAtomic,
      asset: PAYMENT.asset,
      asset_symbol: "USDC",
      network: PAYMENT.networkV2,
      scheme: PAYMENT.scheme,
      pay_to: cfg.payTo,
    },
    schema: SCHEMA,
    endpoints: {
      catalog: `${origin}/`,
      sample: `${origin}/sample`,
      download: `${origin}/download`,
      openapi: `${origin}/openapi.json`,
    },
    x402: {
      x402Version: 2,
      facilitator: cfg.facilitatorUrl,
      payment_header: "PAYMENT-SIGNATURE (v2) or X-PAYMENT (v1)",
    },
    contact: PRODUCT.contactEmail,
  };
}

function openApiDoc(request, cfg) {
  const origin = new URL(request.url).origin;
  return {
    openapi: "3.1.0",
    info: {
      title: PRODUCT.name,
      version: PRODUCT.version,
      description: PRODUCT.shortDescription,
      "x-guidance":
        "Japan Night Loops is a pack of six seamless ambient video loops of Kyoto (Pontocho & the Kamo River), Matsue Castle and Kurashiki Bikan (6x MP4 1664x960 24fps + 6 poster stills, delivered as an encrypted ZIP). GET / returns the product catalog. GET /download takes no input parameters and no request body: call it without payment to receive the x402 (HTTP 402) payment requirements, pay $9.00 USDC on Base (exact scheme), then retry the same GET with the PAYMENT-SIGNATURE header - on successful settlement a JSON response returns the public encrypted-file URL and its decryption key.",
      license: { name: PRODUCT.license },
      contact: { email: PRODUCT.contactEmail },
    },
    servers: [{ url: origin }],
    paths: {
      "/": {
        get: {
          operationId: "getCatalog",
          summary: "Product catalog (free)",
          responses: { "200": { description: "Product description, price and schema as JSON" } },
        },
      },
      "/sample": {
        get: {
          operationId: "getSample",
          summary: "Free preview: product contents and license (free)",
          responses: { "200": { description: "Contents, license and attribution of the paid video pack" } },
        },
      },
      "/download": {
        get: {
          operationId: "downloadVideoPack",
          summary: "Download the Japan Night Loops video pack (paid, x402)",
          description:
            "Returns HTTP 402 with x402 payment requirements when unpaid. Pay $9.00 USDC on Base (exact scheme) and retry with the PAYMENT-SIGNATURE header to receive the download URL and decryption key (JSON).",
          "x-402": { priceUsd: 9.0, network: PAYMENT.networkV2, asset: "USDC" },
          "x-payment-info": {
            price: { mode: "fixed", amount: PAYMENT.priceUsd, currency: "USD" },
            protocols: [{ x402: {} }],
          },
          // Input schema (x402scan discovery): /download takes no input at
          // all — no query parameters and no body. The empty-object
          // requestBody states that explicitly so agents/validators can see
          // there is nothing to send besides the payment header.
          requestBody: {
            required: false,
            description: "No input: this endpoint takes no parameters and no request body. The only input is the x402 payment header (PAYMENT-SIGNATURE) on the paid retry.",
            content: {
              "application/json": {
                schema: { type: "object", properties: {}, additionalProperties: false },
              },
            },
          },
          responses: {
            "200": {
              description: "JSON with the encrypted file URL and its decryption key",
              content: { "application/json": { schema: { type: "object" } } },
            },
            "402": { description: "Payment required (x402 PaymentRequired in PAYMENT-REQUIRED header and JSON body)" },
          },
        },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Dataset storage — never a public URL. Sources in priority order:
//   1. DATASET_ZIP_PATH                    plaintext ZIP file
//   2. DATASET_ENC_PATH (./dataset.zip.enc) AES-256-GCM ciphertext file
//   3. DATASET_ENC_B64_DIR (./data)         ciphertext as base64 text chunks
// Sources 2 and 3 need DATASET_KEY (base64, 32 bytes) and are decrypted in
// memory. A configured-but-unreadable/undecryptable source falls through to
// the next one; if no source yields the ZIP the result is null (configured)
// or undefined (nothing configured), and the caller answers 503 either way —
// an undecryptable dataset is never served.
//
// Encrypted format (produced by scripts/encrypt-dataset.mjs):
//   salt(16) || iv(12) || authTag(16) || ciphertext
//   AES key = scrypt(DATASET_KEY bytes, salt, 32), AES-256-GCM.
// ---------------------------------------------------------------------------

let datasetCache = null; // unused placeholder kept for structure parity

/**
 * Deliverable for the video shop: the encrypted pack lives at a PUBLIC URL
 * (GitHub Release asset). What is sold is the decryption KEY, returned only
 * after settlement. Configured via env:
 *   VIDEO_ENC_URL   public URL of the AES-256-GCM encrypted ZIP
 *   VIDEO_KEY       base64 of 32 random bytes (the decryption key)
 *   VIDEO_FILENAME  plaintext filename inside / after decrypt
 *   VIDEO_SHA256    sha256 hex of the encrypted file (integrity check)
 * Returns the deliverable object, null if partially configured, or
 * undefined if nothing is configured.
 */
async function loadDataset(env) {
  const url = env.VIDEO_ENC_URL || null;
  const key = env.VIDEO_KEY || null;
  if (!url && !key) return undefined;
  if (!url || !key) return null;
  return {
    sourceId: "video-key",
    body: null,
    size: 0,
    deliverable: {
      download_url: url,
      decryption_key_base64: key,
      encrypted_filename: "kyoto-night-loops.zip.enc",
      plaintext_filename: env.VIDEO_FILENAME || PRODUCT.zipFilename,
      sha256_of_encrypted_file: env.VIDEO_SHA256 || null,
      decrypt_instructions:
        "Download download_url, then decrypt with the key (AES-256-GCM, format salt(16)||iv(12)||tag(16)||ciphertext, key = scrypt(keyBytes, salt, 32)). A ready-made decrypt script is included in the product README and in the shop repository.",
    },
  };
}

// ---------------------------------------------------------------------------
// Facilitator calls (PayAI: POST /verify, POST /settle)
// ---------------------------------------------------------------------------

async function facilitatorPost(cfg, path, payload) {
  const headers = { "Content-Type": "application/json" };
  // PayAI's public lane works without a key while free credits last;
  // a merchant API key (JWT) is only needed for authenticated lanes.
  if (cfg.facilitatorApiKey) headers["Authorization"] = `Bearer ${cfg.facilitatorApiKey}`;
  const res = await fetch(`${cfg.facilitatorUrl}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  try {
    return { status: res.status, json: JSON.parse(text) };
  } catch {
    return { status: res.status, json: null, raw: text };
  }
}

/**
 * Validate the client's chosen terms against ours BEFORE calling the
 * facilitator, and build the facilitator request in the client's version.
 * Returns { error } or { facilitatorBody, version }.
 */
function buildFacilitatorBody(request, cfg, paymentPayload) {
  if (!paymentPayload || typeof paymentPayload !== "object") {
    return { error: "payment payload is not a JSON object" };
  }
  const version = paymentPayload.x402Version;

  if (version === 2) {
    const a = paymentPayload.accepted;
    if (!a) return { error: "v2 payment payload is missing `accepted`" };
    if (a.scheme !== PAYMENT.scheme) return { error: "unsupported scheme" };
    if (a.network !== PAYMENT.networkV2) return { error: "unsupported network" };
    if (String(a.asset).toLowerCase() !== PAYMENT.asset.toLowerCase()) return { error: "unsupported asset" };
    if (String(a.payTo).toLowerCase() !== cfg.payTo.toLowerCase()) return { error: "payTo mismatch" };
    if (String(a.amount) !== PAYMENT.amountAtomic) return { error: "amount mismatch" };
    return {
      version,
      facilitatorBody: {
        x402Version: 2,
        paymentPayload,
        paymentRequirements: requirementsV2(request, cfg),
      },
    };
  }

  if (version === 1) {
    if (paymentPayload.scheme !== PAYMENT.scheme) return { error: "unsupported scheme" };
    if (paymentPayload.network !== PAYMENT.networkV1) return { error: "unsupported network" };
    const auth = paymentPayload.payload && paymentPayload.payload.authorization;
    if (!auth) return { error: "v1 payment payload is missing EIP-3009 authorization" };
    if (String(auth.to).toLowerCase() !== cfg.payTo.toLowerCase()) return { error: "payTo mismatch" };
    if (String(auth.value) !== PAYMENT.amountAtomic) return { error: "amount mismatch" };
    return {
      version,
      facilitatorBody: {
        x402Version: 1,
        paymentPayload,
        paymentRequirements: requirementsV1(request, cfg),
      },
    };
  }

  return { error: `unsupported x402Version: ${version}` };
}

// ---------------------------------------------------------------------------
// Paid download flow: verify -> load -> settle -> deliver
// (x402 "authorization" flow, spec section 6.1: funds move only after the
// resource is ready; if settlement fails the file is NOT delivered.)
// ---------------------------------------------------------------------------

async function handleDownload(request, env, cfg) {
  const paymentHeader =
    request.headers.get("PAYMENT-SIGNATURE") || request.headers.get("X-PAYMENT");

  if (!paymentHeader) {
    return paymentRequiredResponse(request, cfg);
  }

  // Never take money for a file we cannot deliver.
  const stored = await loadDataset(env);
  if (stored === undefined) {
    return jsonResponse(
      { error: "deliverable_not_configured", message: "No video deliverable is configured on this deployment (set VIDEO_ENC_URL and VIDEO_KEY)." },
      503
    );
  }
  if (stored === null) {
    return jsonResponse(
      { error: "deliverable_unavailable", message: "The video deliverable is partially configured (VIDEO_ENC_URL and VIDEO_KEY must both be set)." },
      503
    );
  }

  let paymentPayload;
  try {
    paymentPayload = b64decodeJson(paymentHeader);
  } catch {
    return paymentRequiredResponse(request, cfg, "payment header is not valid base64 JSON");
  }

  const built = buildFacilitatorBody(request, cfg, paymentPayload);
  if (built.error) {
    return paymentRequiredResponse(request, cfg, built.error);
  }

  // 1) Verify (read-only; does not move funds)
  let verify;
  try {
    verify = await facilitatorPost(cfg, "/verify", built.facilitatorBody);
  } catch (e) {
    return jsonResponse({ error: "facilitator_unreachable", message: String(e) }, 502);
  }
  if (!verify.json || verify.json.isValid !== true) {
    const reason =
      (verify.json && (verify.json.invalidReason || verify.json.invalidMessage)) ||
      "payment verification failed";
    return paymentRequiredResponse(request, cfg, `invalid payment: ${reason}`);
  }

  // 2) Settle (moves the USDC on-chain via the facilitator)
  let settle;
  try {
    settle = await facilitatorPost(cfg, "/settle", built.facilitatorBody);
  } catch (e) {
    return jsonResponse({ error: "facilitator_unreachable", message: String(e) }, 502);
  }
  if (!settle.json || settle.json.success !== true) {
    const settleResponse = settle.json || { success: false, errorReason: "unknown", transaction: "", network: PAYMENT.networkV2 };
    return jsonResponse(
      { error: "settlement_failed", settle: settleResponse },
      402,
      { "PAYMENT-RESPONSE": b64encodeJson(settleResponse), "X-PAYMENT-RESPONSE": b64encodeJson(settleResponse) }
    );
  }

  // 3) Deliver the decryption key + public encrypted-file URL (JSON),
  // with the settlement receipt header (spec section 5.3)
  const settleResponse = {
    success: true,
    transaction: settle.json.transaction,
    network: settle.json.network,
    payer: settle.json.payer,
  };
  const receipt = b64encodeJson(settleResponse);
  return jsonResponse(
    {
      product: PRODUCT.name,
      license: PRODUCT.license,
      attribution: PRODUCT.attribution,
      ...stored.deliverable,
      settlement: settleResponse,
    },
    200,
    { "PAYMENT-RESPONSE": receipt, "X-PAYMENT-RESPONSE": receipt }
  );
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const cfg = config(env);
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const isHead = request.method === "HEAD";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
          "Access-Control-Allow-Headers": "PAYMENT-SIGNATURE, X-PAYMENT, Content-Type",
          "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE",
        },
      });
    }

    if (request.method !== "GET" && !isHead) {
      return jsonResponse({ error: "method_not_allowed" }, 405);
    }

    switch (path) {
      case "/healthz": {
        const res = jsonResponse({ status: "ok" });
        return isHead ? new Response(null, { status: res.status, headers: res.headers }) : res;
      }
      case "/":
      case "/.well-known/x402": {
        const res = jsonResponse(catalog(request, cfg));
        return isHead ? new Response(null, { status: res.status, headers: res.headers }) : res;
      }
      case "/sample": {
        const body = {
          product: PRODUCT.name,
          license: PRODUCT.license,
          attribution: PRODUCT.attribution,
          contents: SCHEMA,
          note: "Preview still and a short preview clip are linked from the product page. The paid /download returns the encrypted full pack URL and its decryption key.",
        };
        const res = jsonResponse(body);
        return isHead ? new Response(null, { status: res.status, headers: res.headers }) : res;
      }
      case "/openapi.json": {
        const res = jsonResponse(openApiDoc(request, cfg));
        return isHead ? new Response(null, { status: res.status, headers: res.headers }) : res;
      }
      case "/download":
        return handleDownload(request, env, cfg);
      default:
        return jsonResponse(
          { error: "not_found", catalog: `${url.origin}/` },
          404
        );
    }
  },
};
