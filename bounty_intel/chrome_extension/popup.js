// Configuration is stored per-browser in chrome.storage.local, never in source.
// The original hosted dashboard was decommissioned on 2026-09-11, so there is
// no default endpoint: set both values from the form in the popup.

const COOKIE_NAME = "__Host-Intigriti.Web.Researcher";
const COOKIE_URL = "https://app.intigriti.com";

async function loadConfig() {
  const { dashboardUrl = "", apiKey = "" } = await chrome.storage.local.get(["dashboardUrl", "apiKey"]);
  return { dashboardUrl: dashboardUrl.replace(/\/+$/, ""), apiKey };
}

async function saveConfig() {
  const status = document.getElementById("status");
  const dashboardUrl = document.getElementById("dashboard-url").value.trim();
  const apiKey = document.getElementById("api-key").value.trim();

  await chrome.storage.local.set({ dashboardUrl, apiKey });
  status.className = "status ok";
  status.textContent = "Settings saved.";
}

async function restoreConfig() {
  const { dashboardUrl, apiKey } = await loadConfig();
  document.getElementById("dashboard-url").value = dashboardUrl;
  document.getElementById("api-key").value = apiKey;
}

async function syncIntigriti() {
  const btn = document.getElementById("sync-btn");
  const status = document.getElementById("status");

  btn.disabled = true;
  status.className = "status loading";
  status.textContent = "Reading cookie...";

  try {
    const { dashboardUrl, apiKey } = await loadConfig();

    if (!dashboardUrl) {
      status.className = "status err";
      status.textContent = "No dashboard URL set. Enter your Bounty Intel URL below and save.";
      btn.disabled = false;
      return;
    }

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
    if (apiKey) {
      // API key auth
      resp = await fetch(`${dashboardUrl}/api/v1/sync`, {
        method: "POST",
        headers: {
          "X-API-Key": apiKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ source: "intigriti", cookie: cookie.value }),
      });
    } else {
      // Session cookie auth (if user is logged into dashboard in same browser)
      resp = await fetch(`${dashboardUrl}/sync/intigriti`, {
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

document.addEventListener("DOMContentLoaded", restoreConfig);
document.getElementById("sync-btn").addEventListener("click", syncIntigriti);
document.getElementById("save-btn").addEventListener("click", saveConfig);
