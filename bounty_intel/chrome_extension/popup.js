// Configuration — update these after deployment
const DASHBOARD_URL = "https://bounty-dashboard-887002731862.europe-west1.run.app";
const API_KEY = ""; // Set your BOUNTY_INTEL_API_KEY here

const COOKIE_NAME = "__Host-Intigriti.Web.Researcher";
const COOKIE_URL = "https://app.intigriti.com";

async function syncIntigriti() {
  const btn = document.getElementById("sync-btn");
  const status = document.getElementById("status");

  btn.disabled = true;
  status.className = "status loading";
  status.textContent = "Reading cookie...";

  try {
    // Read the HttpOnly cookie using chrome.cookies API
    const cookie = await chrome.cookies.get({
      url: COOKIE_URL,
      name: COOKIE_NAME,
    });

    if (!cookie || !cookie.value) {
      status.className = "status err";
      status.textContent = "No Intigriti session found. Open app.intigriti.com and log in first.";
      btn.disabled = false;
      return;
    }

    status.textContent = "Cookie found. Syncing...";

    // Send cookie to dashboard API
    const formData = new URLSearchParams();
    formData.append("cookie", cookie.value);

    // Use the web endpoint (session-authenticated) or API endpoint
    let resp;
    if (API_KEY) {
      // API key auth
      resp = await fetch(`${DASHBOARD_URL}/api/v1/sync`, {
        method: "POST",
        headers: {
          "X-API-Key": API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ source: "intigriti", cookie: cookie.value }),
      });
    } else {
      // Session cookie auth (if user is logged into dashboard in same browser)
      resp = await fetch(`${DASHBOARD_URL}/sync/intigriti`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData,
        credentials: "include",
      });
    }

    if (resp.ok) {
      const text = await resp.text();
      status.className = "status ok";
      status.textContent = "Synced successfully!";
    } else {
      status.className = "status err";
      status.textContent = `Sync failed: HTTP ${resp.status}`;
    }
  } catch (err) {
    status.className = "status err";
    status.textContent = `Error: ${err.message}`;
  }

  btn.disabled = false;
}
