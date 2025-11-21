// test-complex-app.js
// Massive realistic frontend bundle simulation
// Contains secrets, tokens, AWS keys, DB URLs, critical endpoints, dynamic requests

const CONFIG = {
  API_BASE: "https://api.prod.example.com/v2",
  GRAPHQL_ENDPOINT: "https://graphql.example.com/prod",
  STRIPE_KEY: "pk_live_51H3f9xK2n9vJ9...", // Fake but realistic
  MAPBOX_TOKEN: "pk.eyJ1IjoiZGV2dGVhbSIsImEiOiJjbG9wZW4tdGVzdCJ9.xxxxxxxx",
  SENTRY_DSN: "https://1234567890@o123456.ingest.sentry.io/1234567",
};

const secrets = {
  // Hardcoded API key (should be flagged)
  openai_key: "sk-ant-sid-1234567890abcdef1234567890abcdef12345678",
  // Another one in different format
  "map-api-key": "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  firebaseConfig: {
    apiKey: "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    authDomain: "myapp-prod.firebaseapp.com",
    projectId: "myapp-prod-12345",
    storageBucket: "myapp-prod-12345.appspot.com",
    messagingSenderId: "123456789012",
    appId: "1:123456789012:web:abcdef1234567890abcdef"
  }
};

// AWS keys - very common leak
const awsConfig = {
  accessKeyId: "AKIAX7Y8Z9A1B2C3D4E5",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
  region: "us-east-1"
};

// MongoDB connection string (leaked in env but hardcoded here by mistake)
const DB_URL = "mongodb+srv://admin:SuperSecretPass123!@cluster0.xxxxx.mongodb.net/myapp?retryWrites=true&w=majority";

// PostgreSQL URL from old dev environment
const OLD_DB = "postgresql://user:password123@db.prod.internal:5432/appdb";

// Redis with password
const redisUrl = "redis://:p@ssw0rd!@redis-12345.c1.us-east1-2.gce.cloud.redislabs.com:12345";

// JWT token left after debugging session
const debugToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4sJ7gJ7gJ7gJ7gJ7gJ7gJ7gJ7g";

// Passwords in code (very bad practice)
const adminPass = "Admin@2025!SuperSecure";
const backupPassword = 'myvoiceismypassportverifyme';

// Emails scattered
const supportEmail = "security@example.com";
const devEmail = "john.doe+test@company.com";

// IPs
const internalApi = "http://10.0.50.27:8080/internal/debug";
const backupServer = "192.168.1.100";

// Dynamic endpoint construction
const userId = localStorage.getItem("uid") || "12345";
const apiUrl = `${CONFIG.API_BASE}/users/${userId}/profile`;
const paymentUrl = `https://payments.example.com/api/v1/charge?amount=999&token=card_1J...`;

// Axios instance
axios.defaults.baseURL = CONFIG.API_BASE;
axios.defaults.headers.common['Authorization'] = `Bearer ${debugToken}`;

// Fetch calls
fetch("https://api.example.com/api/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "admin@example.com", password: adminPass })
});

fetch(`/api/users/${userId}/admin/panel`, { method: "GET" })
  .then(r => r.json())
  .then(data => console.log("Admin data:", data));

// Template literal madness
const dynamicQuery = `https://api.example.com/v1/search?q=${searchTerm}&apikey=${secrets.openai_key}&page=1`;

// Axios calls
axios.post("/auth/login", { username: "admin", password: "letmein123" });
axios.get("/admin/users/all");
axios.put(`/user/${userId}/password`, { newPassword });
axios.delete("/admin/delete-everything");

// Axios with config object
axios({
  method: 'post',
  url: '/user/12345/reset-password',
  data: { token: "abc123", newPassword: "P@ssw0rd!" }
});

// XHR - old school
const xhr = new XMLHttpRequest();
xhr.open("POST", "https://legacy.example.com/api/auth", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({ api_key: "legacy_key_1234567890abcdef" }));

// GraphQL query with token
const gql = require('graphql-tag');

const LOGIN_MUTATION = gql`
  mutation Login($email: String!, $password: String!) {
    login(email: $email, password: $password) {
      token
      user { id name role }
    }
  }
`;

// Dynamic fetch with computed URL
const endpoints = ["/profile", "/settings", "/billing", "/admin/secrets"];
endpoints.forEach(path => {
  fetch(`${CONFIG.API_BASE}${path}`, {
    headers: { "X-API-KEY": "x-api-key-1234567890abcdef1234567890" }
  });
});

// Fake obfuscation attempt (common in leaked bundles)
const _0x4e3f = ["c2tfdGVzdF8xMjM0NTY3ODkwYWJjZGVm", "aHR0cHM6Ly9zZWNyZXQuYXBpL2tleQ=="];
const realKey = atob(_0x4e3f[0]); // decodes to sk_test_1234567890abcdef
fetch(atob(_0x4e3f[1]), { headers: { Authorization: "Bearer " + realKey } });

// Fake safe-looking keys (should NOT trigger high-severity)
const fakeKey = "dummy_key_12345";
const placeholder = "YOUR_API_KEY_HERE";
const example = "abc123xyz";

// More critical endpoints
const criticalPaths = [
  "/api/admin/dashboard",
  "/v3/oauth/token",
  "/auth/callback",
  "/user/verify-email",
  "/payment/webhook",
  "/admin/delete-account-permanently"
];

// Loop to simulate real usage
criticalPaths.forEach(p => axios.get(p));

// Stripe + PayPal + other payment keys
const stripe = Stripe("pk_live_51H3f9xK2n9vJ9...");
const paypalClientId = "AXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

// Final admin backdoor (left by angry dev)
if (window.location.hash === "#godmode") {
  console.log("%c GOD MODE ACTIVATED ", "color: red; font-size: 30px");
  localStorage.setItem("role", "superadmin");
  localStorage.setItem("bypass_2fa", "true");
  fetch("/admin/grant-all-permissions", { method: "POST" });
}

// End of file - total ~350 lines, very realistic
console.log("App initialized with leaked credentials");