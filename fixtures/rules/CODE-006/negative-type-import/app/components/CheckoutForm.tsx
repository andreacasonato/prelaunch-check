"use client";

import type Stripe from "stripe";
import { type Stripe as S2 } from "stripe";

export function CheckoutForm(props: { session?: Stripe.Checkout.Session; s?: S2 }) {
  return <form>{props.session?.id}</form>;
}
