# DockLight Payment Hub

Payment Hub is a dependency-free shared capability for DockLight PWAs. It owns payment method/provider registration, safe public settings, connectivity-aware availability, idempotent attempt lifecycle, provider handoff metadata, and normalized outcomes. It has no BoothBoss, cart, order, inventory, event, receipt, or accounting dependencies.

## Public API

Create an isolated registry with `createPaymentHub()`. The returned host-facing API is:

- `registerProvider(adapter)`
- `listMethods(config, {online})`
- `beginPayment({attemptId, amount, currency, method, context})`
- `cancelPayment(attemptId)`
- `confirmExternalPayment(attemptId)`
- `applyProviderResult(attemptId, result)`
- `normalizeProviderResult(result)`
- `serializePaymentRecord(attempt)`
- `loadPaymentRecord(record)` for restoring a durable attempt
- `isPaid(attempt)` and `getAttempt(attemptId)`

Built-in adapters cover Cash, Stripe, PayPal/Venmo, Cash App, Zelle, and Other/custom. Capabilities state whether a rail is verified or manual, requires internet, and supports link, QR, or deep-link handoff. Current browser-only external rails are manual; they are never marked verified.

## Minimal PWA integration

```html
<script src="payment-hub/index.js"></script>
<script>
const hub = DockLightPaymentHub.createPaymentHub();
const methods = hub.listMethods(savedPublicSettings, {online: navigator.onLine});
const method = methods.find(item => item.id === selectedMethodId && item.available);
const attempt = hub.beginPayment({
  attemptId: crypto.randomUUID(),
  amount: orderTotal,
  currency: 'USD',
  method,
  context: {orderId}
});
await paymentStore.put(hub.serializePaymentRecord(attempt));

// After the merchant checks a manual provider app/account:
const completed = hub.confirmExternalPayment(attempt.id);
await paymentStore.put(hub.serializePaymentRecord(completed));
if (hub.isPaid(completed)) await hostOrders.markPaid(orderId);
</script>
```

The host supplies durable storage and owns order creation and paid-order side effects. On reload, pass its stored record to `loadPaymentRecord()` before canceling or confirming. Provider adapters receive only payment-neutral `amount`, `currency`, `attemptId`, public method settings, and an opaque non-secret `context`.

## Security boundary

Configuration is recursively rejected when a key indicates card/CVV data, bank credentials, passwords, access tokens, API keys, or client/provider secrets. Only public merchant handoff data and non-secret provider references belong in a PWA. Backend credentials stay server-side. DockLight is not merchant of record and does not hold merchant funds.
