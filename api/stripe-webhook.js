// XANKONG Control — Stripe webhook (Vercel serverless)
// Set env STRIPE_WEBHOOK_SECRET = whsec_... from Stripe Dashboard after endpoint is created

const crypto = require('crypto');

function parseSig(header) {
  const out = { t: null, v1: [] };
  if (!header) return out;
  for (const part of header.split(',')) {
    const [k, v] = part.split('=');
    if (k === 't') out.t = v;
    if (k === 'v1') out.v1.push(v);
  }
  return out;
}

function verify(rawBody, sigHeader, secret, toleranceSec = 300) {
  if (!secret) return { ok: false, reason: 'missing_secret' };
  const { t, v1 } = parseSig(sigHeader);
  if (!t || !v1.length) return { ok: false, reason: 'bad_header' };
  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(t));
  if (Number.isFinite(age) && age > toleranceSec) return { ok: false, reason: 'timestamp' };
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${t}.${rawBody}`, 'utf8')
    .digest('hex');
  const ok = v1.some((sig) => {
    try {
      return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(sig, 'utf8'));
    } catch {
      return false;
    }
  });
  return ok ? { ok: true } : { ok: false, reason: 'signature' };
}

const seen = new Map();
function once(id) {
  if (seen.has(id)) return false;
  seen.set(id, Date.now());
  if (seen.size > 500) {
    const cutoff = Date.now() - 3600_000;
    for (const [k, ts] of seen) if (ts < cutoff) seen.delete(k);
  }
  return true;
}

async function fulfillCheckout(session) {
  const email = session.customer_details?.email || session.customer_email || null;
  const meta = session.metadata || {};
  console.log(
    JSON.stringify({
      type: 'fulfill_checkout',
      session_id: session.id,
      payment_status: session.payment_status,
      mode: session.mode,
      email,
      metadata: meta,
      amount_total: session.amount_total,
      currency: session.currency,
    })
  );
  return true;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  }

  const rawBody =
    typeof req.body === 'string'
      ? req.body
      : Buffer.isBuffer(req.body)
        ? req.body.toString('utf8')
        : JSON.stringify(req.body || {});

  const secret = process.env.STRIPE_WEBHOOK_SECRET || '';
  const sig = req.headers['stripe-signature'] || '';

  if (secret) {
    const v = verify(rawBody, sig, secret);
    if (!v.ok) {
      console.warn('stripe_sig_fail', v.reason);
      return res.status(400).json({ error: 'invalid_signature', reason: v.reason });
    }
  } else {
    console.warn('STRIPE_WEBHOOK_SECRET not set — accepting without verify (set in Vercel env)');
  }

  let event;
  try {
    event =
      typeof req.body === 'object' && req.body && !Buffer.isBuffer(req.body)
        ? req.body
        : JSON.parse(rawBody);
  } catch {
    return res.status(400).json({ error: 'invalid_json' });
  }

  if (!once(event.id || rawBody.slice(0, 64))) {
    return res.status(200).json({ received: true, duplicate: true });
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
      case 'checkout.session.async_payment_succeeded': {
        const session = event.data?.object || {};
        if (
          session.payment_status === 'paid' ||
          event.type === 'checkout.session.async_payment_succeeded'
        ) {
          await fulfillCheckout(session);
        }
        break;
      }
      case 'checkout.session.async_payment_failed':
        console.log('async_payment_failed', event.data?.object?.id);
        break;
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted':
        console.log(
          JSON.stringify({
            type: event.type,
            subscription: event.data?.object?.id,
            status: event.data?.object?.status,
            customer: event.data?.object?.customer,
          })
        );
        break;
      case 'invoice.paid':
      case 'invoice.payment_failed':
        console.log(
          JSON.stringify({
            type: event.type,
            invoice: event.data?.object?.id,
            customer: event.data?.object?.customer,
            amount_paid: event.data?.object?.amount_paid,
          })
        );
        break;
      default:
        console.log('unhandled', event.type);
    }
  } catch (err) {
    console.error('handler_error', err);
    return res.status(500).json({ error: 'handler_error' });
  }

  return res.status(200).json({ received: true });
};
