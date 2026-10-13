import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";

export const stripe = new Stripe(import.meta.env.VITE_STRIPE_KEY);
export const admin = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);
