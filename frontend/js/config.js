/* ------------------------------------------------------------------
   CONFIG
   USE_MOCK = true  -> app runs fully in the browser (localStorage),
                       no backend needed. Good for demo / UI review.
   USE_MOCK = false -> app calls your Flask API at API_BASE.
------------------------------------------------------------------- */
window.CONFIG = {
  USE_MOCK: false,
  API_BASE: "/api",
  RISK_SAFE_MAX: 30,        // 0-29  => Safe
  RISK_FAKE_MIN: 60         // 60+   => Fake, between => Suspicious
};
