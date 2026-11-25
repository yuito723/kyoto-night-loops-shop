/**
 * Node http adapter for the x402 shop.
 *
 * src/app.js is written against the web-standard fetch API (it is a port of
 * the Cloudflare Workers version). This file converts Node IncomingMessage /
 * ServerResponse to Request / Response so the shop logic stays identical.
 * Node standard library only — no dependencies.
 *
 * Environment:
 *   PORT              listen port (Render sets this; default 10000)
 *   PAY_TO            USDC recipient on Base (default in app.js if unset)
 *   FACILITATOR_URL   x402 facilitator base URL (default: PayAI)
 *   FACILITATOR_API_KEY  optional facilitator bearer key
 *   DATASET_ZIP_PATH  path to a plaintext dataset ZIP (optional; Render
 *                     Secret File: /etc/secrets/dataset.zip)
 *   DATASET_KEY       base64 of 32 random bytes; decrypts the encrypted
 *                     dataset (Dashboard only — never commit this)
 *   DATASET_ENC_PATH  encrypted ZIP file (default ./dataset.zip.enc)
 *   DATASET_ENC_B64_DIR  dir with dataset.enc.b64.NNN chunks committed in
 *                     the repo (default ./data; production source on Render)
 */
import { createServer } from "node:http";
import app from "./src/app.js";

const env = {
  PAY_TO: process.env.PAY_TO,
  FACILITATOR_URL: process.env.FACILITATOR_URL,
  FACILITATOR_API_KEY: process.env.FACILITATOR_API_KEY,
  DATASET_ZIP_PATH: process.env.DATASET_ZIP_PATH,
  DATASET_KEY: process.env.DATASET_KEY,
  DATASET_ENC_PATH: process.env.DATASET_ENC_PATH,
  DATASET_ENC_B64_DIR: process.env.DATASET_ENC_B64_DIR,
  VIDEO_ENC_URL: process.env.VIDEO_ENC_URL,
  VIDEO_KEY: process.env.VIDEO_KEY,
  VIDEO_FILENAME: process.env.VIDEO_FILENAME,
  VIDEO_SHA256: process.env.VIDEO_SHA256,
};

const port = Number(process.env.PORT) || 10000;

const server = createServer(async (req, res) => {
  try {
    const proto = req.headers["x-forwarded-proto"] || "http";
    const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${port}`;
    const url = `${proto}://${host}${req.url}`;

    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (Array.isArray(v)) for (const item of v) headers.append(k, item);
      else if (v !== undefined) headers.set(k, v);
    }

    const request = new Request(url, { method: req.method, headers });

    const response = await app.fetch(request, env);

    const outHeaders = {};
    response.headers.forEach((value, key) => {
      outHeaders[key] = value;
    });
    res.writeHead(response.status, outHeaders);
    if (response.body) {
      const buf = Buffer.from(await response.arrayBuffer());
      res.end(buf);
    } else {
      res.end();
    }
  } catch (err) {
    console.error("request failed:", err);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
    }
    res.end(JSON.stringify({ error: "internal_error" }));
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`kyoto-loop-x402-shop listening on :${port}`);
  console.log(
    `dataset source: ${
      env.DATASET_ZIP_PATH ||
      (env.DATASET_KEY ? "encrypted (DATASET_ENC_PATH / DATASET_ENC_B64_DIR)" : "(not configured)")
    }`
  );
});
