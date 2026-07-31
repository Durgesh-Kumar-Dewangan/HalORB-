document.addEventListener("DOMContentLoaded", () => {
  const tokenInput = document.getElementById("token");
  const apiKeyInput = document.getElementById("apiKey");
  const statusEl = document.getElementById("status");

  chrome.storage.local.get(["pairingToken", "safeBrowsingApiKey"], (result) => {
    tokenInput.value = result.pairingToken || "";
    apiKeyInput.value = result.safeBrowsingApiKey || "";
  });

  document.getElementById("save").addEventListener("click", () => {
    const pairingToken = tokenInput.value.trim();
    const safeBrowsingApiKey = apiKeyInput.value.trim();

    chrome.storage.local.set({ pairingToken, safeBrowsingApiKey }, () => {
      statusEl.textContent = "Saved.";
      setTimeout(() => (statusEl.textContent = ""), 2000);
    });
  });
});
