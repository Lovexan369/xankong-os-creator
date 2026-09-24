module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({
    ok: true,
    service: 'xankong-control',
    ts: new Date().toISOString(),
    webhook: '/api/stripe-webhook',
  });
};
