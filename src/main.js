//import { open } from '@tauri-apps/plugin-dialog';
const { open } = window.__TAURI_PLUGIN_DIALOG__;
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// --- UI Elements ---
const decryptBtn = document.getElementById("decrypt-vault-btn");
const encryptBtn = document.getElementById("encrypt-folder-btn");
const targetDisplay = document.getElementById("target-path-display");

const keySelectionDiv = document.getElementById("key-selection");
const keyBtn = document.getElementById("select-key-btn");
const keyDisplay = document.getElementById("key-path-display");

const settingsGroup = document.querySelector(".settings-group");
const advancedOptions = document.querySelector(".advanced-options");
const actionBtn = document.getElementById("action-btn");

// --- State ---
let currentMode = "ENCRYPT"; // Default state
let targetPath = null;
let keyPath = null;

// --- Shared Selection Handler ---
function handleSelection(selectedPath) {
  if (selectedPath) {
    targetPath = selectedPath;
    targetDisplay.textContent = targetPath;

    // Trigger Smart UI
    if (targetPath.endsWith(".obv")) {
      enableDecryptMode();
    } else {
      enableEncryptMode();
    }
  }
}

// --- Native File/Folder Selection ---
decryptBtn.addEventListener("click", async () => {
  const selectedPath = await open({
    multiple: false,
    directory: false,
    title: 'Select Vault to Decrypt',
    filters: [{ name: 'Ombracrypt Vault', extensions: ['obv'] }] // Locks native explorer to .obv only
  });
  handleSelection(selectedPath);
});

encryptBtn.addEventListener("click", async () => {
  const selectedPath = await open({
    multiple: false,
    directory: true, 
    title: 'Select a Folder to Encrypt'
  });
  handleSelection(selectedPath);
});

keyBtn.addEventListener("click", async () => {
  // Open the native Linux file explorer locked to .obk files
  const selectedKey = await open({
    multiple: false,
    title: 'Select Key File',
    filters: [{
      name: 'Ombracrypt Key',
      extensions: ['obk']
    }]
  });

  if (selectedKey) {
    keyPath = selectedKey;
    keyDisplay.textContent = keyPath;
  }
});

// --- UI Transformation Functions ---
function enableDecryptMode() {
  currentMode = "DECRYPT";
  keySelectionDiv.style.display = "block";
  settingsGroup.style.display = "none";
  advancedOptions.style.display = "none";
  actionBtn.textContent = "Unlock Vault";
  actionBtn.style.backgroundColor = "#28a745";
}

function enableEncryptMode() {
  currentMode = "ENCRYPT";
  keyPath = null;
  keySelectionDiv.style.display = "none";
  keyDisplay.textContent = "No key selected";
  settingsGroup.style.display = "flex";
  advancedOptions.style.display = "block";
  actionBtn.textContent = "Lock Vault";
  actionBtn.style.backgroundColor = "var(--accent)";
}

// --- Bridge to Rust Backend ---
const cryptoForm = document.getElementById("crypto-form");
const statusMsg = document.getElementById("status-msg");

// --- Progress Bar Listener ---
const progressContainer = document.getElementById("progress-container");
const progressBar = document.getElementById("progress-bar");

listen('crypto-progress', (event) => {
  progressContainer.style.display = "block";
  progressBar.style.width = event.payload + "%";
});

cryptoForm.addEventListener("submit", async (e) => {
  e.preventDefault(); // Prevent standard HTML form submission (page reload)

  if (!targetPath) {
    statusMsg.textContent = "Please select a target folder or vault first.";
    statusMsg.style.color = "#ff4444";
    return;
  }

  const cipher = document.getElementById("cipher-algo").value;
  const kem = document.getElementById("kem-algo").value;
  const mainPin = document.getElementById("main-pin").value;
  const panicPin = document.getElementById("panic-pin").value;

progressContainer.style.display = "block";
  progressBar.style.width = "0%";


  statusMsg.textContent = "Executing cryptographic operations. Do not interrupt or close the application.";
  statusMsg.style.color = "var(--accent)";
  
  try {
    // Send the payload across the bridge to lib.rs
    const response = await invoke("process_cryptography", {
      mode: currentMode,
      targetPath: targetPath,
      keyPath: keyPath,
      cipher: cipher,
      kem: kem,
      mainPin: mainPin,
      panicPin: panicPin
    });

    // Display Rust's response in the UI
    statusMsg.textContent = response;
    statusMsg.style.color = "#28a745"; 
  } catch (error) {
    statusMsg.textContent = "Error: " + error;
    statusMsg.style.color = "#ff4444";
  }
});