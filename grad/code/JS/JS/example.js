// Example API endpoints for testing

// Fetch API examples
fetch("https://api.example.com/v1/user/login?redirect=1", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer TEST_BEARER_TOKEN_123456789"
    },
    body: JSON.stringify({
        username: "testuser",
        password: "SecretPass123!"
    })
});

// Axios GET
axios.get("https://example.com/api/products?limit=50");

// Axios POST
axios.post("https://example.com/api/auth/reset", {
    email: "user@example.com"
});

// XHR example
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://example.com/api/admin/settings", true);
xhr.send();

// Hardcoded secrets for detection testing
const API_KEY = "FAKEAPIKEY1234567890987654321";
var secret_token = "test_secret_token_ABC_987654";
let jsonToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.TEST.TEST_SIGNATURE";

const AWS_ACCESS_KEY = "AKIA123456789EXAMPLE";
const AWS_SECRET_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab";

// Database URLs
const MONGO_URL = "mongodb+srv://user:pass@cluster.example.mongodb.net/db";
const POSTGRES_URL = "postgresql://admin:password123@db.example.com:5432/prod";

// Random endpoints
let userDetails = "https://example.com/user/profile";
let adminPanel = "https://example.com/admin/dashboard";
let paymentUrl = "https://example.com/api/payment/charge";

// Emails & IPs
var supportEmail = "support@example.com";
var backendIP = "192.168.1.50";
