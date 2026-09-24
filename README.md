# XANKONG Control

Production control plane: **live Coinbase markets**, AI draft studio, Stripe Pro ($29/mo), signed webhooks.

**Owner:** Dmitry Nikolaevich Koval  
**Stack:** static HTML + Vercel serverless · Stripe live · GitHub

## URLs

| Resource | Link |
|----------|------|
| App (production) | https://xankong-os-creator-kongxan.vercel.app |
| Buy Pro | https://buy.stripe.com/5kQ3cv65Ebds4YW3j09IQ04 |
| Webhook | `POST /api/stripe-webhook` |
| Health | `GET /api/health` |
| Repo | https://github.com/Lovexan369/xankong-os-creator |

## Features

- Live BTC/ETH/SOL/TON tickers (Coinbase public API, 15s poll)
- Site / Swarm / Security draft generator (proposal-only, free quota 3/mo)
- Pro unlock via Stripe Payment Link → `?paid=pro` → localStorage
- Stripe webhook with **HMAC signature verification** (`timingSafeEqual`, raw body, ±300s)
- Lead capture (localStorage)

## Env (Vercel)

```
STRIPE_WEBHOOK_SECRET=whsec_...
```

Already set as sensitive on project `xankong-os-creator`.

## Stripe (live)

| Object | ID |
|--------|-----|
| Product | `prod_VJrGQKrVrorNLf` XANKONG Control Pro |
| Price | `price_1UJDXcGWUjgSlWSunJPlYS72` $29/month |
| Payment Link | `plink_1UJDY6GWUjgSlWSucdK2KfAU` |
| Webhook | `we_1UJDZBGWUjgSlWSu1ewKLLyb` |

Events: checkout.session.* · customer.subscription.* · invoice.paid/failed

## Deploy

Push to `main` → Vercel auto-deploy (git linked).

**Required:** disable Deployment Protection for Production so Stripe webhooks reach `/api/stripe-webhook`.

## Security posture

- Webhook: fail-closed without secret; constant-time HMAC compare
- No nexus-flame / false-E2EE messenger in this product surface
- Drafts are proposal-only (no spend/deploy execution from UI)
- Recovery codes / secrets must never be committed

## Local

```bash
npx serve .
# open http://localhost:3000
```

Webhook local test: Stripe CLI `stripe listen --forward-to localhost:3000/api/stripe-webhook`
