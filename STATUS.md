# XANKONG — Master status (2026-09-24)

## DONE

- [x] Live markets UI (Coinbase)
- [x] Draft studio (site/swarm/security)
- [x] Stripe product + $29/mo price + Payment Link
- [x] Stripe webhook endpoint (live) + events
- [x] Signature verification (raw body, timingSafeEqual, tolerance)
- [x] Vercel env STRIPE_WEBHOOK_SECRET
- [x] GitHub repo api/stripe-webhook.js
- [x] Health endpoint api/health.js
- [x] Pro redirect handling (?paid=pro)

## BLOCKED ON YOU

- [ ] Vercel Deployment Protection OFF (Production)
- [ ] Confirm Control index.html is the live homepage
- [ ] Rotate any leaked GitHub recovery codes (if still active)
- [ ] Optional: Formspree / CRM for leads (CONFIG.formEndpoint)

## NOT IN THIS PRODUCT (by design)

- nexus-flame deploy (security council: BLOCK)
- Full Signal messenger production (separate track)
- K8s / docker-compose full stack (infra templates only)

## MONEY PATH

1. Share https://buy.stripe.com/5kQ3cv65Ebds4YW3j09IQ04
2. Or site Buy Pro button after public deploy
3. Webhook logs fulfill_checkout on paid session
4. Optional: wire fulfill_checkout → email/CRM
