'use client';

import Stripe from "stripe";

const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY!);

export function CheckoutButton() {
  return <button onClick={() => stripe.checkout.sessions.create({ mode: "payment" })}>Buy credits</button>;
}
