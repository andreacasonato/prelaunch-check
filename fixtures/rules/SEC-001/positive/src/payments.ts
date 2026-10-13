import Stripe from "stripe";

// TODO: move to env before launch
const stripe = new Stripe("__PLC_FAKE_STRIPE_SK_LIVE__");

export async function charge(amount: number) {
  return stripe.paymentIntents.create({ amount, currency: "usd" });
}
