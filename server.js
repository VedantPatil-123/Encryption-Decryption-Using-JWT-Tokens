// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import * as jose from "jose";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public")); // serve the frontend

// Load 32-byte secret (Base64) -> Uint8Array
const secretB64 = process.env.JWE_SECRET_BASE64;
if (!secretB64) {
  console.error("Missing JWE_SECRET_BASE64 in .env");
  process.exit(1);
}
const secret = new Uint8Array(Buffer.from(secretB64, "base64"));

/**
 * POST /api/encrypt
 * body: { plaintext: string, expiresIn?: string }  // e.g., "1h", "10m"
 * returns: { token: string }
 */
app.post("/api/encrypt", async (req, res) => {
  try {
    const { plaintext, expiresIn = "45s" } = req.body || {};
    if (typeof plaintext !== "string" || !plaintext.length) {
      return res.status(400).json({ error: "plaintext is required" });
    }

    const token = await new jose.EncryptJWT({ data: plaintext })
      .setProtectedHeader({ alg: "dir", enc: "A256GCM" }) // direct symmetric, AES-256-GCM
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .encrypt(secret);

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "encryption failed" });
  }
});

/**
 * POST /api/decrypt
 * body: { token: string }
 * returns: { plaintext: string, iat: number, exp: number }
 */
app.post("/api/decrypt", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (typeof token !== "string" || !token.length) {
      return res.status(400).json({ error: "token is required" });
    }

    const { payload, protectedHeader } = await jose.jwtDecrypt(token, secret, {
      clockTolerance: 5, // seconds tolerance
    });

    // Expect payload like { data: "...", iat, exp }
    res.json({
      plaintext: payload.data,
      iat: payload.iat,
      exp: payload.exp,
      alg: protectedHeader.alg,
      enc: protectedHeader.enc,
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "invalid or expired token" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log(`JWE demo running at http://localhost:${port}`)
);

