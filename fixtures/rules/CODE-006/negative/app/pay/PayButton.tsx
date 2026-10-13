'use client';
import { loadStripe } from "@stripe/stripe-js";
import { createClient } from "@supabase/supabase-js";

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
// "stripe" mentioned in a comment and in a string: "import Stripe from 'stripe'"
