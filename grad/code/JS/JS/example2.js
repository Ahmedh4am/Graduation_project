// hard_test.js
// Large & complex JS file for testing secret / endpoint scanners

"use strict";

// =========================
// Configuration & constants
// =========================

const BASE_URL = "https://api.hard-example.com";
const CDN_URL = "https://cdn.hard-example.com/assets";
const LEGACY_API = "https://old-api.hard-example.com/v1";
const INTERNAL_API = "https://10.0.0.5:8443/api/internal";

const FRONTEND_VERSION = "4.12.7";
const BUILD_HASH = "f93a7c1b39c647b59f91c06e836f1234";

// Hardcoded fake secrets
const PUBLIC_API_KEY = "FAKEPUBLICAPIKEY_1234567890_ABCDEFGH";
const STRIPE_PUBLIC_KEY = "pk_test_51HARDTESTSTRIPEPUBLICKEYFAKE";
const STRIPE_SECRET_KEY = "sk_test_51HARDTESTSTRIPESECRETKEYFAKE";
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzFAKE";
const GOOGLE_API_KEY = "AIzaSyDUMMYFAKEKEY1234567890abcdEFGHijk";

// AWS-style access + secret
const AWS_ACCESS_KEY_ID = "AKIAHARDTESTACCESSKEY12";
const AWS_SECRET_ACCESS_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd";

// JWTs (fake)
const SERVICE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJ1c2VySWQiOiIxMjM0Iiwicm9sZSI6ImFkbWluIn0." +
  "Q2hlY2tTaWduYXR1cmVEYXRhVG9NYWtlSXRIYXJk";

const ANOTHER_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJwcm9qZWN0SWQiOiJob3RzY2FuIiwic2NvcGUiOiJmcmVlIn0." +
  "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA";

// Database URLs (fake)
const MONGO_MAIN =
  "mongodb+srv://admin:SuperPassw0rd!@cluster0.mongodb.net/main-db";
const MONGO_LOGS =
  "mongodb+srv://logger:LogPass123@cluster1.mongodb.net/log-db";
const POSTGRES_MAIN =
  "postgresql://pgadmin:P0stgresPass!@db.hard-example.com:5432/prod";
const REDIS_URL = "redis://:RedisPass123@cache.hard-example.com:6379/0";

// SMTP & emails
const SMTP_HOST = "smtp.hard-example.com";
const SMTP_USER = "noreply@hard-example.com";
const SMTP_PASS = "NoreplySmtpP@ssw0rd";

let supportEmail = "support@hard-example.com";
let abuseEmail = "abuse@hard-example.com";

// IPs
const INTERNAL_IP = "10.0.0.5";
const DB_IP = "10.0.0.20";
const REDIS_IP = "10.0.0.30";
const EXTERNAL_IP = "203.0.113.77";

// =========================
// Generic HTTP client
// =========================

class HttpClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  request(method, path, options = {}) {
    const url = this.baseUrl + path;
    const headers = options.headers || {};
    const body = options.body ? JSON.stringify(options.body) : undefined;

    return fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Client-Version": FRONTEND_VERSION,
        ...headers,
      },
      body,
    }).then((res) => {
      return res.json().catch(() => ({}));
    });
  }

  get(path, params = {}) {
    const query = new URLSearchParams(params).toString();
    const fullPath = query ? `${path}?${query}` : path;
    return this.request("GET", fullPath);
  }

  post(path, body) {
    return this.request("POST", path, { body });
  }

  put(path, body) {
    return this.request("PUT", path, { body });
  }

  del(path) {
    return this.request("DELETE", path);
  }
}

const apiClient = new HttpClient(BASE_URL);

// =========================
// Authentication flows
// =========================

// Hardcoded test credentials
const TEST_ADMIN_USER = "admin_test";
const TEST_ADMIN_PASS = "AdminPassw0rd!";
const TEST_USER_EMAIL = "demo.user@hard-example.com";
const TEST_USER_PASSWORD = "UserDemoP@ss123";
const MASTER_PASSWORD = "MasterP@ssw0rd!";

// Login flow (fetch, axios, XHR mixed)

function loginWithFetch(email, password) {
  return fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Test-Header": "login-fetch",
    },
    body: JSON.stringify({ email, password }),
  }).then((r) => r.json());
}

function loginWithAxios(email, password) {
  return axios.post(`${BASE_URL}/api/auth/login`, {
    email,
    password,
  });
}

function legacyLogin(username, password) {
  var xhr = new XMLHttpRequest();
  xhr.open("POST", `${LEGACY_API}/login`, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(JSON.stringify({ username, password }));
}

// Token refresh
function refreshToken(refreshToken) {
  return apiClient.post("/api/auth/refresh", { refreshToken });
}

// OAuth callback example
function handleOAuthCallback(code, state) {
  return fetch(`${BASE_URL}/api/auth/oauth/callback?code=${code}&state=${state}`, {
    method: "GET",
    headers: {
      "X-Flow": "oauth",
      Authorization: `Bearer ${SERVICE_JWT}`,
    },
  }).then((r) => r.json());
}

// =========================
// User & profile endpoints
// =========================

async function getUserProfile(userId) {
  return apiClient.get(`/api/users/${userId}/profile`, {
    include: "settings,permissions",
  });
}

async function updateUserProfile(userId, profile) {
  return apiClient.put(`/api/users/${userId}/profile`, profile);
}

async function listUsers(page = 1, limit = 25) {
  return apiClient.get("/api/users", { page, limit, sort: "createdAt:desc" });
}

async function changePassword(userId, oldPass, newPass) {
  return apiClient.post(`/api/users/${userId}/change-password`, {
    oldPassword: oldPass,
    newPassword: newPass,
  });
}

async function requestPasswordReset(email) {
  return apiClient.post("/api/auth/reset/request", { email });
}

async function confirmPasswordReset(token, newPass) {
  return apiClient.post("/api/auth/reset/confirm", {
    token,
    newPassword: newPass,
  });
}

// =========================
// Admin & internal endpoints
// =========================

function getAdminDashboardStats() {
  return axios.get(`${BASE_URL}/api/admin/dashboard?range=7d`, {
    headers: {
      Authorization: `Bearer ${SERVICE_JWT}`,
      "X-Admin-Mode": "true",
    },
  });
}

function getAuditLogs(page) {
  return axios.get(`${BASE_URL}/api/admin/audit-logs`, {
    params: { page, limit: 50, sort: "timestamp:desc" },
    headers: {
      Authorization: `Bearer ${SERVICE_JWT}`,
    },
  });
}

function internalSyncJob(jobId) {
  // internal IP, weird port, path params & query params
  return fetch(
    `${INTERNAL_API}/jobs/${jobId}/sync?reindex=true&recalculate=1`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${SERVICE_JWT}`,
        "X-Internal-Job": "sync",
      },
      body: JSON.stringify({ batchSize: 1000 }),
    }
  );
}

// =========================
// Payment endpoints
// =========================

async function createCheckoutSession(userId, planId) {
  const body = {
    userId,
    planId,
    currency: "USD",
    mode: "subscription",
    stripePublicKey: STRIPE_PUBLIC_KEY,
  };
  return apiClient.post("/api/payment/stripe/checkout", body);
}

async function handleStripeWebhook(rawBody, signatureHeader) {
  // Usually backend, but we fake it here
  const endpointSecret = "whsec_FAKESTRIPEWEBHOOKSECRET";
  console.log("Stripe webhook test:", endpointSecret, rawBody, signatureHeader);
}

function getInvoices(userId) {
  return axios.get(`${BASE_URL}/api/payment/invoices`, {
    params: { userId, limit: 20 },
    headers: {
      Authorization: `Bearer ${SERVICE_JWT}`,
    },
  });
}

// =========================
// Logging, metrics, experiments
// =========================

function logClientEvent(eventName, payload) {
  return fetch(`${BASE_URL}/api/logs/client`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Client-Version": FRONTEND_VERSION,
    },
    body: JSON.stringify({
      event: eventName,
      payload,
      buildHash: BUILD_HASH,
    }),
  });
}

function sendMetric(name, value, tags = {}) {
  const url = `${BASE_URL}/api/metrics/ingest`;
  const body = {
    name,
    value,
    tags,
    ts: Date.now(),
  };
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Metric-Token": "METRIC_TOKEN_123456789_FAKE",
    },
    body: JSON.stringify(body),
  });
}

const experimentConfig = {
  experiments: [
    {
      key: "new-onboarding-flow",
      variants: ["control", "variantA", "variantB"],
      apiEndpoint: `${BASE_URL}/api/experiments/assign`,
      secretKey: "EXPERIMENT_SECRET_KEY_SHOULD_NOT_BE_HERE",
    },
    {
      key: "pricing-page-v2",
      variants: ["control", "v2"],
      apiEndpoint: `${BASE_URL}/api/experiments/assign`,
      secretKey: "ANOTHER_EXPERIMENT_SECRET",
    },
  ],
};

// =========================
// Minified / obfuscated-style code
// =========================

(function () {
  // simulated minified calls
  function a(u, m, d) {
    return fetch(u, {
      method: m,
      headers: { "X-Mini": "1", Authorization: "Bearer MINIFIEDTOKEN_123456" },
      body: d ? JSON.stringify(d) : undefined,
    });
  }

  const u1 = "https://api.hard-example.com/api/minified/log";
  const u2 = "https://api.hard-example.com/api/minified/track?ev=click";
  const u3 = "/api/minified/internal/state?refresh=true";

  a(u1, "POST", { msg: "minified-log", lvl: "debug" });
  a(u2, "GET");
  a(BASE_URL + u3, "GET");

  // random pattern mixing
  var s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.minified.payload.signature";
  var p = "password=minifiedPassword123";
  var k = "api_key=MINIFIED_FAKE_KEY_123456789";
})();

// =========================
// Another custom client
// =========================

const http = {
  get: function (url, headers) {
    return fetch(url, {
      method: "GET",
      headers: headers || {},
    });
  },
  post: function (url, data, headers) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(headers || {}) },
      body: JSON.stringify(data),
    });
  },
};

function loadDashboard(userId, token) {
  return http.get(`${BASE_URL}/api/dashboard?userId=${userId}`, {
    Authorization: `Bearer ${token}`,
  });
}

function postFeedback(userId, message, rating) {
  return http.post(
    `${BASE_URL}/api/feedback`,
    { userId, message, rating },
    {
      Authorization: `Bearer ${SERVICE_JWT}`,
      "X-Feedback-Source": "web",
    }
  );
}

// =========================
// File upload & downloads
// =========================

function uploadAvatar(userId, file) {
  const url = `${BASE_URL}/api/users/${userId}/avatar`;
  const formData = new FormData();
  formData.append("avatar", file);
  formData.append("token", "AVATAR_UPLOAD_TOKEN_FAKE");

  return fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SERVICE_JWT}`,
    },
    body: formData,
  });
}

function downloadReport(reportId) {
  return fetch(`${BASE_URL}/api/reports/${reportId}/download?format=pdf`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${SERVICE_JWT}`,
    },
  }).then((r) => r.blob());
}

// =========================
// Weird patterns & misc
// =========================

// Mixed inline URLs
const mixed = [
  "https://hard-example.com/login",
  "https://hard-example.com/register",
  "https://hard-example.com/user/profile",
  "https://hard-example.com/admin/panel",
  "/api/misc/ping",
  "/api/misc/deep-status?full=true&level=debug",
  "http://localhost:3000/api/dev/endpoint",
  "http://127.0.0.1:8080/api/local/test",
];

mixed.forEach((u) => {
  if (u.indexOf("/api/") !== -1) {
    console.log("API endpoint detected in mixed list:", u);
  }
});

// Hardcoded credentials object
const credentials = {
  admin: {
    username: "root_admin",
    password: "RootAdminP@ss",
  },
  readonly: {
    username: "readonly_user",
    password: "ReadonlyP@ss123",
  },
  serviceAccount: {
    clientId: "svc-1234567890abcdef",
    clientSecret: "SERVICE_CLIENT_SECRET_SHOULD_NOT_BE_HERE",
  },
};

// Legacy global variables that look like secrets
var secret = "legacySecretKey_1234567890";
var auth_token = "legacyAuthToken_ABCDEFGHIJKLMNO";
var apiKey = "legacyApiKey_1234567890FAKE";
var access_token = "ACCESS_TOKEN_FOR_DEBUG_ONLY_DO_NOT_USE";

// Random long hex strings
var hex1 =
  "4f9b2a3c1e5d7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2";
var hex2 =
  "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

// =========================
// Manual test runner
// =========================

async function runTestSequence() {
  console.log("Starting hard test sequence...");

  try {
    await loginWithFetch(TEST_USER_EMAIL, TEST_USER_PASSWORD);
    await loginWithAxios(TEST_USER_EMAIL, TEST_USER_PASSWORD);
    legacyLogin(TEST_ADMIN_USER, TEST_ADMIN_PASS);

    await getUserProfile("12345");
    await updateUserProfile("12345", { displayName: "Demo User" });
    await listUsers(1, 50);
    await changePassword("12345", TEST_USER_PASSWORD, "MyNewP@ssw0rd!");
    await requestPasswordReset("reset.user@hard-example.com");
    await confirmPasswordReset("FAKE_RESET_TOKEN_123456", "AnotherP@ssword!");
    await getAdminDashboardStats();
    await getAuditLogs(1);
    await internalSyncJob("job-12345");
    await createCheckoutSession("12345", "plan_pro");
    await getInvoices("12345");

    await logClientEvent("test-event", { foo: "bar" });
    await sendMetric("test-metric", 42, { env: "test" });

    await loadDashboard("12345", SERVICE_JWT);
    await postFeedback("12345", "Great product!", 5);

    console.log("Hard test sequence completed.");
  } catch (e) {
    console.error("Hard test sequence error:", e);
  }
}

// Just to have the function referenced
window.runHardTest = runTestSequence;
