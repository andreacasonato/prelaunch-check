import Stripe from "stripe";

// Quick hack for the demo: charge from the browser.
const stripe = new Stripe("__PLC_FAKE_STRIPE_SK_LIVE__");

export function pay(amount: number) {
  return stripe.paymentIntents.create({ amount, currency: "eur" });
}
