// عنوان الباك إند. غيّره بعد ما ترفع الـ API على الـ Cloud.
// Backend base URL. Change it after deploying the API (no trailing slash).
window.PHISHGUARD_CONFIG = {
  API_BASE_URL: "http://127.0.0.1:5000",
  REQUEST_TIMEOUT_MS: 70000, // free cloud tiers can take ~30-60s to wake up
};
