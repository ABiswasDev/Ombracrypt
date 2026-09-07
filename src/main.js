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

const settingsGroup = document.getElementById("settings-group");
const advancedOptions = document.getElementById("advanced-options");
const actionBtn = document.getElementById("action-btn");

// --- Password Validation Elements ---
const mainPinInput = document.getElementById("main-pin");
const confirmPinInput = document.getElementById("confirm-pin");
const confirmGroup = document.getElementById("confirm-password-group");
const matchMsg = document.getElementById("password-match-msg");
const strengthContainer = document.getElementById("password-strength-container");
const strengthBar = document.getElementById("password-strength-bar");
const strengthText = document.getElementById("password-strength-text");

// --- Progress & ETA Elements ---
const progressContainer = document.getElementById("progress-container");
const progressBar = document.getElementById("progress-bar");
const progressPercent = document.getElementById("progress-percent");
const progressEta = document.getElementById("progress-eta");
const statusMsg = document.getElementById("status-msg");

// --- State ---
let currentMode = "ENCRYPT"; // Default state
let targetPath = null;
let keyPath = null;
let operationStartTime = 0; // Tracks when cryptography starts

// --- Real-time Password Validation Logic ---
mainPinInput.addEventListener("input", () => {
  if (currentMode === "ENCRYPT") {
    checkPasswordStrength(mainPinInput.value);
    checkPasswordMatch();
  }
});

confirmPinInput.addEventListener("input", () => {
  if (currentMode === "ENCRYPT") {
    checkPasswordMatch();
  }
});

function checkPasswordStrength(password) {
  if (!password) {
    strengthContainer.style.display = "none";
    strengthText.style.display = "none";
    return;
  }

  let strength = 0;
  if (password.length >= 8) strength += 1;
  if (password.length >= 12) strength += 1;
  if (/[A-Z]/.test(password)) strength += 1;
  if (/[0-9]/.test(password)) strength += 1;
  if (/[^A-Za-z0-9]/.test(password)) strength += 1;

  strengthContainer.style.display = "block";
  strengthText.style.display = "block";

  if (strength <= 2) {
    strengthBar.style.width = "33%";
    strengthBar.style.backgroundColor = "#ff4444"; 
    strengthText.textContent = "Strength: Weak";
    strengthText.style.color = "#ff4444";
  } else if (strength === 3 || strength === 4) {
    strengthBar.style.width = "66%";
    strengthBar.style.backgroundColor = "#ffbb33"; 
    strengthText.textContent = "Strength: Moderate";
    strengthText.style.color = "#ffbb33";
  } else {
    strengthBar.style.width = "100%";
    strengthBar.style.backgroundColor = "#00C851"; 
    strengthText.textContent = "Strength: Strong";
    strengthText.style.color = "#00C851";
  }
}

function checkPasswordMatch() {
  const p1 = mainPinInput.value;
  const p2 = confirmPinInput.value;

  if (!p2) {
    matchMsg.textContent = "";
    return;
  }

  if (p1 === p2) {
    matchMsg.textContent = "Passwords match ✓";
    matchMsg.style.color = "#00C851"; 
  } else {
    matchMsg.textContent = "Passwords do not match ✗";
    matchMsg.style.color = "#ff4444"; 
  }
}

// --- Shared Selection Handler ---
function handleSelection(selectedPath) {
  if (selectedPath) {
    targetPath = selectedPath;
    targetDisplay.textContent = targetPath;

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
    filters: [{ name: 'Ombracrypt Vault', extensions: ['obv'] }]
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
  const selectedKey = await open({
    multiple: false,
    title: 'Select Key File',
    filters: [{ name: 'Ombracrypt Key', extensions: ['obk'] }]
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
  
  confirmGroup.style.display = "none";
  confirmPinInput.required = false;
  strengthContainer.style.display = "none";
  strengthText.style.display = "none";

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

  confirmGroup.style.display = "flex";
  confirmPinInput.required = true;
  if (mainPinInput.value) {
    checkPasswordStrength(mainPinInput.value);
  }

  actionBtn.textContent = "Lock Vault";
  actionBtn.style.backgroundColor = "var(--accent)";
}

// --- Bridge to Rust Backend & ETA Logic ---
let streamStartTime = 0; // New variable to track when streaming actually starts

listen('crypto-progress', (event) => {
  const currentProgress = event.payload;
  
  progressContainer.style.display = "block";
  progressBar.style.width = currentProgress + "%";
  
  if (progressPercent) progressPercent.textContent = currentProgress + "%";

  if (currentProgress < 50) {
    if (progressEta) progressEta.textContent = "Preparing files & generating keys...";
  } else if (currentProgress === 50 || (currentMode === "DECRYPT" && currentProgress === 60)) {
    // RESET the timer right as the fast streaming loop begins!
    streamStartTime = Date.now();
    if (progressEta) progressEta.textContent = "Calculating ETA...";
  } else if (currentProgress >= 100) {
    if (progressEta) progressEta.textContent = "Finalizing disk write...";
  } else {
    // Only calculate speed based on the active streaming phase
    const elapsedMs = Date.now() - streamStartTime;
    
    // Calculate how far along we are in just the streaming portion
    const phaseProgress = currentMode === "ENCRYPT" ? (currentProgress - 50) : (currentProgress - 60);
    
    // Calculate ms per 1% of progress
    const msPerPercent = elapsedMs / phaseProgress;
    const remainingPercents = 100 - currentProgress; 
    const remainingMs = msPerPercent * remainingPercents;
    
    const totalSeconds = Math.floor(remainingMs / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = (totalSeconds % 60).toString().padStart(2, '0');
    
    // Explicitly added "remaining" so the user is never confused
    if (progressEta) progressEta.textContent = `ETA: ${minutes}m ${seconds}s remaining`;
  }
});

const cryptoForm = document.getElementById("crypto-form");

cryptoForm.addEventListener("submit", async (e) => {
  e.preventDefault(); 

  if (!targetPath) {
    statusMsg.textContent = "Please select a target folder or vault first.";
    statusMsg.style.color = "#ff4444";
    return;
  }

  const mainPin = mainPinInput.value;
  const confirmPin = confirmPinInput.value;

  if (currentMode === "ENCRYPT" && mainPin !== confirmPin) {
    statusMsg.textContent = "Error: Passwords do not match. Please verify your master password.";
    statusMsg.style.color = "#ff4444";
    return;
  }

  const cipher = document.getElementById("cipher-algo").value;
  const kem = document.getElementById("kem-algo").value;
  const panicPin = document.getElementById("panic-pin").value;

  // Reset UI for a fresh operation
  progressContainer.style.display = "block";
  progressBar.style.width = "0%";
  if (progressPercent) progressPercent.textContent = "0%";
  if (progressEta) progressEta.textContent = "Calculating ETA...";
  
  statusMsg.textContent = "Executing cryptographic operations. Do not interrupt or close the application.";
  statusMsg.style.color = "var(--accent)";
  
  // Start the timer directly before executing Rust payload
  operationStartTime = Date.now();
  
  try {
    const response = await invoke("process_cryptography", {
      mode: currentMode,
      targetPath: targetPath,
      keyPath: keyPath,
      cipher: cipher,
      kem: kem,
      mainPin: mainPin,
      panicPin: panicPin
    });

    statusMsg.textContent = response;
    statusMsg.style.color = "#28a745"; 
  } catch (error) {
    statusMsg.textContent = "Error: " + error;
    statusMsg.style.color = "#ff4444";
  }
});