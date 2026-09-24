/**
 * XANKONG Control — Stripe webhook (Vercel Node serverless)
 *
 * Signature verification (manual, no stripe SDK):
 * 1. Read RAW body bytes (bodyParser disabled)
 * 2. Parse Stripe-Signature: t=<ts>,v1=<hex>[,v1=...]
 * 3. signed_payload = `${t}.${rawBody}`
 * 4. expected = HMAC-SHA256(secret, signed_payload) as hex
 * 5. timing-safe compare against each v1; reject if timestamp skew > 300s
 *
 * Env: STRIPE_WEBHOOK_SECRET=whsec_... (required in production)
 */

const crypto = require('crypto');

// Critical: do not let Vercel/Node parse JSON before verification
module.exports.config = {
  api: {
    bodyParser: false,
  },
};

const TOLERANCE_SEC = 300;

/**
 * Read the complete raw request body as a UTF-8 string.
 * Must match the exact bytes Stripe signed.
 */
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    // Already buffered (some runtimes)
    if (Buffer.isBuffer(req.body)) {
      resolve(req.body.toString('utf8'));
      return;
    }
    if (typeof req.body === 'string') {
      resolve(req.body);
      return;
    }

    const chunks = [];
    req.on('data', (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', reject);
  });
}

/**
 * Parse Stripe-Signature header → { t, v1[] }
 * Ignores v0 (test helper) and unknown schemes.
 */
function parseStripeSignature(header) {
  const result = { t: null, v1: [] };
  if (!header || typeof header !== 'string') return result;

  for (const part of header.split(',')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key === 't') result.t = value;
    else if (key === 'v1' && value) result.v1.push(value);
  }
  return result;
}

/**
 * Constant-time hex compare. Returns false if lengths differ.
 */
function safeEqualHex(a, b) {
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length === 0 || ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

/**
 * Verify Stripe webhook signature.
 * @returns {{ ok: true, timestamp: number } | { ok: false, reason: string }}
 */
function verifyStripeSignature(rawBody, signatureHeader, secret, toleranceSec = TOLERANCE_SEC) {
  if (!secret || typeof secret !== 'string' || !secret.startsWith('whsec_')) {
    return { ok: false, reason: 'invalid_or_missing_secret' };
  }
  if (!rawBody && rawBody !== '') {
    return { ok: false, reason: 'empty_body' };
  }
  if (!signatureHeader) {
    return { ok: false, reason: 'missing_stripe_signature_header' };
  }

  const { t, v1 } = parseStripeSignature(signatureHeader);
  if (!t || !/^\d+$/.test(t)) {
    return { ok: false, reason: 'missing_or_invalid_timestamp' };
  }
  if (!v1.length) {
    return { ok: false, reason: 'no_v1_signatures' };
  }

  const ts = Number(t);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > toleranceSec) {
    return { ok: false, reason: 'timestamp_outside_tolerance' };
  }

  // signed_payload = timestamp + '.' + raw body (exact bytes as UTF-8 string)
  const signedPayload = `${t}.${rawBody}`;
  const expected = crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');

  // Accept if ANY v1 matches (supports secret rotation with multiple active secrets)
  let matched = false;
  for (const sig of v1) {
    if (safeEqualHex(expected, sig)) {
      matched = true;
      break;
    }
  }

  if (!matched) {
    return { ok: false, reason: 'signature_mismatch' };
  }

  return { ok: true, timestamp: ts };
}

// Best-effort de-dupe within a warm instance
const seen = new Map();
function once(id) {
  if (!id) return true;
  if (seen.has(id)) return false;
  seen.set(id, Date.now());
  if (seen.size > 500) {
    const cutoff = Date.now() - 3_600_000;
    for (const [k, ts] of seen) {
      if (ts < cutoff) seen.delete(k);
    }
  }
  return true;
}

async function fulfillCheckout(session) {
  const email = session.customer_details?.email || session.customer_email || null;
  console.log(
    JSON.stringify({
      type: 'fulfill_checkout',
      session_id: session.id,
      payment_status: session.payment_status,
      mode: session.mode,
      email,
      metadata: session.metadata || {},
      amount_total: session.amount_total,
      currency: session.currency,
    })
  );
  // TODO: grant Pro access in DB/CRM
  return true;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    console.error('body_read_error', err && err.message);
    return res.status(400).json({ error: 'body_read_failed' });
  }

  const secret = process.env.STRIPE_WEBHOOK_SECRET || '';
  const signatureHeader = req.headers['stripe-signature'] || '';

  // Fail closed: never process unverified events when secret is configured or required
  const requireVerify = process.env.NODE_ENV === 'production' || Boolean(secret);
  if (!secret) {
    console.error('STRIPE_WEBHOOK_SECRET is not set');
    if (requireVerify) {
      return res.status(500).json({ error: 'webhook_secret_not_configured' });
    }
  } else {
    const verification = verifyStripeSignature(rawBody, signatureHeader, secret);
    if (!verification.ok) {
      console.warn(
        JSON.stringify({
          type: 'stripe_sig_fail',
          reason: verification.reason,
          has_header: Boolean(signatureHeader),
          body_len: rawBody.length,
        })
      );
      return res.status(400).json({
        error: 'invalid_signature',
        reason: verification.reason,
      });
    }
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return res.status(400).json({ error: 'invalid_json' });
  }

  if (!event || typeof event !== 'object' || !event.type) {
    return res.status(400).json({ error: 'invalid_event' });
  }

  if (!once(event.id)) {
    return res.status(200).json({ received: true, duplicate: true });
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
      case 'checkout.session.async_payment_succeeded': {
        const session = (event.data && event.data.object) || {};
        if (
          session.payment_status === 'paid' ||
          event.type === 'checkout.session.async_payment_succeeded'
        ) {
          await fulfillCheckout(session);
        }
        break;
      }
      case 'checkout.session.async_payment_failed':
        console.log(
          JSON.stringify({
            type: 'async_payment_failed',
            session_id: event.data && event.data.object && event.data.object.id,
          })
        );
        break;
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = (event.data && event.data.object) || {};
        console.log(
          JSON.stringify({
            type: event.type,
            subscription: sub.id,
            status: sub.status,
            customer: sub.customer,
          })
        );
        break;
      }
      case 'invoice.paid':
      case 'invoice.payment_failed': {
        const inv = (event.data && event.data.object) || {};
        console.log(
          JSON.stringify({
            type: event.type,
            invoice: inv.id,
            customer: inv.customer,
            amount_paid: inv.amount_paid,
          })
        );
        break;
      }
      default:
        console.log(JSON.stringify({ type: 'unhandled', event_type: event.type }));
    }
  } catch (err) {
    console.error('handler_error', err && err.message);
    // Return 500 so Stripe retries
    return res.status(500).json({ error: 'handler_error' });
  }

  return res.status(200).json({ received: true });
};
