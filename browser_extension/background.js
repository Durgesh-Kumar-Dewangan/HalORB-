/**
 * Tray Status Indicator - Website Safety Reporter
 * ------------------------------------------------
 * Watches the active tab's URL, evaluates safety using:
 *   1) Local heuristics (fast, always on, no API key needed)
 *   2) Google Safe Browsing v4 lookup (optional - only runs if the user has
 *      entered their own free API key in the options page)
 * and reports the combined result to the local Tray Status Indicator app
 * running on this same PC (http://127.0.0.1:8765/report).
 *
 * Nothing here sends your browsing data anywhere except:
 *   - Google's Safe Browsing API (only the current URL, only if you supplied
 *     an API key), which is the standard reputation-check service used by
 *     Chrome's own "Safe Browsing" feature.
 *   - Your own machine's localhost app (127.0.0.1) - never leaves your PC.
 */

const REPORT_ENDPOINT = "http://127.0.0.1:8765/report";

// Well-known brand names commonly impersonated in phishing domains.
// Heuristic only - a domain merely containing one of these words is NOT
// proof of anything; it's one weak signal combined with others below.
const BRAND_KEYWORDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "netflix",
  "facebook", "instagram", "bankofamerica", "chase", "wellsfargo",
  "outlook", "office365", "icloud", "coinbase", "binance",
];

// TLDs that see disproportionate abuse for phishing/scam campaigns.
// Weak signal only - most sites using these TLDs are perfectly legitimate.
const WATCHED_TLDS = ["zip", "mov", "top", "xyz", "tk", "gq", "ml", "cf", "work", "click"];

function getStoredSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["pairingToken", "safeBrowsingApiKey"], (result) => {
      resolve({
        pairingToken: result.pairingToken || "",
        safeBrowsingApiKey: result.safeBrowsingApiKey || "",
      });
    });
  });
}

function isIpLiteralHost(hostname) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipv4.test(hostname) || hostname.includes(":"); // crude IPv6 check too
}

function isPunycodeHost(hostname) {
  return hostname.split(".").some((label) => label.startsWith("xn--"));
}

function brandImpersonationScore(hostname) {
  const lower = hostname.toLowerCase();
  let score = 0;
  for (const brand of BRAND_KEYWORDS) {
    if (lower.includes(brand)) {
      // Contains a brand name but has extra hyphens/words -> classic
      // typosquat/impersonation pattern, e.g. "paypal-secure-login.xyz"
      const labelPart = lower.split(".")[0];
      if (labelPart !== brand && (labelPart.includes("-") || labelPart.length > brand.length + 6)) {
        score += 2;
      }
    }
  }
  return score;
}

function tldRiskScore(hostname) {
  const parts = hostname.split(".");
  const tld = parts[parts.length - 1];
  return WATCHED_TLDS.includes(tld) ? 1 : 0;
}

function runHeuristics(urlString) {
  const reasons = [];
  let score = 0;
  let hostname = "";

  try {
    const u = new URL(urlString);
    hostname = u.hostname;

    if (!["http:", "https:"].includes(u.protocol)) {
      return { suspicious: false, reasons: [] }; // ignore chrome://, file://, etc.
    }

    if (isIpLiteralHost(hostname)) {
      score += 2;
      reasons.push("URL uses a raw IP address instead of a domain name");
    }

    if (isPunycodeHost(hostname)) {
      score += 2;
      reasons.push("domain uses punycode (possible look-alike/homograph domain)");
    }

    const brandScore = brandImpersonationScore(hostname);
    if (brandScore > 0) {
      score += brandScore;
      reasons.push("domain pattern resembles brand impersonation/typosquatting");
    }

    score += tldRiskScore(hostname);
    if (tldRiskScore(hostname) > 0) {
      reasons.push(`domain uses a TLD (.${hostname.split(".").pop()}) frequently abused in scams`);
    }

    if (u.protocol === "http:" && (hostname.includes("login") || hostname.includes("secure") || hostname.includes("account"))) {
      score += 1;
      reasons.push("login/account-related page served without HTTPS");
    }
  } catch (e) {
    return { suspicious: false, reasons: [] };
  }

  return { suspicious: score >= 2, reasons };
}

async function checkSafeBrowsing(urlString, apiKey) {
  if (!apiKey) {
    return { checked: false, unsafe: false, reasons: [] };
  }
  try {
    const body = {
      client: { clientId: "tray-status-indicator", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: urlString }],
      },
    };
    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );
    if (!resp.ok) {
      return { checked: false, unsafe: false, reasons: [] };
    }
    const data = await resp.json();
    if (data && Array.isArray(data.matches) && data.matches.length > 0) {
      const types = [...new Set(data.matches.map((m) => m.threatType))];
      return { checked: true, unsafe: true, reasons: [`Google Safe Browsing flagged: ${types.join(", ")}`] };
    }
    return { checked: true, unsafe: false, reasons: [] };
  } catch (e) {
    return { checked: false, unsafe: false, reasons: [] };
  }
}

async function evaluateAndReport(urlString) {
  if (!urlString || !/^https?:\/\//i.test(urlString)) {
    return; // skip internal/browser pages
  }

  const settings = await getStoredSettings();
  const heuristic = runHeuristics(urlString);
  const safeBrowsing = await checkSafeBrowsing(urlString, settings.safeBrowsingApiKey);

  const unsafe = heuristic.suspicious || safeBrowsing.unsafe;
  const reasons = [...heuristic.reasons, ...safeBrowsing.reasons];

  if (!settings.pairingToken) {
    return; // extension not paired with the desktop app yet
  }

  try {
    await fetch(REPORT_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: settings.pairingToken,
        url: urlString,
        safe: !unsafe,
        reasons,
      }),
    });
  } catch (e) {
    // Desktop app probably isn't running - fail silently.
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active && tab.url) {
    evaluateAndReport(tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab && tab.url) {
      evaluateAndReport(tab.url);
    }
  });
});
