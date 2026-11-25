# Kyoto Night Loops — x402 shop

Self-hosted x402 (HTTP 402) sales endpoint for the **Kyoto Night Loops** video
pack: two seamless ambient loops of Pontocho / Kamo River, Kyoto, built from
MLIT PLATEAU 3D city data (Blender) and cinematized with Wan 2.2 (Apache 2.0).

- `GET /` — product catalog (JSON)
- `GET /download` — x402-gated ($9.00 USDC on Base, exact scheme, PayAI
  facilitator). After settlement it returns a JSON deliverable: the public
  URL of the AES-256-GCM encrypted ZIP plus its decryption key
  (key-after-payment delivery).
- `GET /healthz` — health check

The encrypted file `kyoto-night-loops.zip.enc` lives in this repository
(ciphertext only — safe to be public). The key exists only in the Render
environment variable `VIDEO_KEY`.

Decrypt: format salt(16)‖iv(12)‖tag(16)‖ciphertext, AES key =
scrypt(keyBytes, salt, 32). A ready-made snippet is in the product README
inside the ZIP.

Data attribution: Source: MLIT PLATEAU (https://www.mlit.go.jp/plateau/),
processed/edited. City model data: Kyoto City / MLIT, PDL 1.0
(CC BY 4.0 compatible).
