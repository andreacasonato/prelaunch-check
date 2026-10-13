'use client';

import { loadStripe } from "@stripe/stripe-js";

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);

export function CheckoutButton() {
  return (
    <button onClick={async () => { await stripePromise; await fetch("/api/checkout", { method: "POST" }); }}>
      Buy credits
    </button>
  );
}
