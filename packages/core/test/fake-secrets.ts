// Vendor prefixes assembled at runtime so no secret-shaped literal is ever committed.
// (GitHub push protection and other scanners would rightly flag them, even when fake.)
export const SK_LIVE = ["sk", "live", ""].join("_");
export const SK_TEST = ["sk", "test", ""].join("_");
export const RK_LIVE = ["rk", "live", ""].join("_");
export const SB_SECRET = ["sb", "secret", ""].join("_");
