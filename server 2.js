import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.FLW_SECRET_HASH;

if (!SECRET) {
  console.warn("WARNING: FLW_SECRET_HASH is not set. Webhook requests will be rejected.");
}

// Keep the raw request body so HMAC-SHA256 verification is exact.
app.use(express.raw({ type: "application/json" }));

function validSignature(rawBody, signature) {
  if (!SECRET || !signature) return false;
  const expected = crypto
    .createHmac("sha256", SECRET)
    .update(rawBody)
    .digest("base64");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    service: "Flutterwave webhook",
    endpoint: "/webhooks/flutterwave"
  });
});

app.post("/webhooks/flutterwave", async (req, res) => {
  const signature = req.get("flutterwave-signature");

  if (!validSignature(req.body, signature)) {
    return res.status(401).json({ ok: false, error: "Invalid signature" });
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.status(400).json({ ok: false, error: "Invalid JSON" });
  }

  // Acknowledge quickly. Flutterwave requires a 200 response.
  console.log("Flutterwave event:", JSON.stringify({
    id: payload.id,
    type: payload.type,
    transactionId: payload.data?.id,
    status: payload.data?.status,
    reference: payload.data?.reference
  }));

  // TODO: Add your business logic here.
  // For Shopify, use the payment reference/metadata to locate the
  // corresponding Shopify order, then update it only after independently
  // verifying the transaction with Flutterwave's API.

  return res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`Webhook server listening on port ${PORT}`);
});
