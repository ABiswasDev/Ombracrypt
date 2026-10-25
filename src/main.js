const { open } = window.__TAURI_PLUGIN_DIALOG__;
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// --- Mode Tab Elements ---
const modeEncryptTab = document.getElementById("mode-encrypt-tab");
const modeDecryptTab = document.getElementById("mode-decrypt-tab");

// --- Path Selection Elements ---
const selectSourceBtn = document.getElementById("select-source-btn");
const targetDisplay = document.getElementById("target-path-display");

const selectOutputBtn = document.getElementById("select-output-btn");
const outputDisplay = document.getElementById("output-path-display");

const keyModeWrapper = document.getElementById("key-mode-wrapper");
const keyModeSelect = document.getElementById("key-mode-select");
const selectKeyBtn = document.getElementById("select-key-btn");
const keyDisplay = document.getElementById("key-path-display");

const spaceTelemetryBox = document.getElementById("space-telemetry-box");
const spaceTelemetryText = document.getElementById("space-telemetry-text");

// --- Settings & Action Elements ---
const settingsGroup = document.getElementById("settings-group");
const kemAlgoGroup = document.getElementById("kem-algo-group");
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

// --- Deception Validation Elements ---
const deceptionInput = document.getElementById("deception-passcode");
const confirmDeceptionInput = document.getElementById("confirm-deception-passcode");
const deceptionMatchMsg = document.getElementById("deception-match-msg");

// --- Progress & ETA Elements ---
const progressContainer = document.getElementById("progress-container");
const progressBar = document.getElementById("progress-bar");
const progressPercent = document.getElementById("progress-percent");
const progressEta = document.getElementById("progress-eta");
const statusMsg = document.getElementById("status-msg");

// --- Application State ---
let currentMode = "ENCRYPT"; // "ENCRYPT" or "DECRYPT"
let targetPath = null;
let outputDir = null;
let keyPath = null;
let storageCheckPassed = false;
let streamStartTime = 0;

// --- Mode Switching Logic ---
modeEncryptTab.addEventListener("click", () => switchMode("ENCRYPT"));
modeDecryptTab.addEventListener("click", () => switchMode("DECRYPT"));

function switchMode(newMode) {
  currentMode = newMode;
  targetPath = null;
  outputDir = null;
  keyPath = null;
  storageCheckPassed = false;

  targetDisplay.textContent = "No source selected";
  outputDisplay.textContent = "No output destination selected";
  keyDisplay.textContent = "No key location selected";
  spaceTelemetryBox.style.display = "none";
  statusMsg.textContent = "";
  actionBtn.disabled = false;

  if (currentMode === "ENCRYPT") {
    modeEncryptTab.classList.add("active-tab");
    modeDecryptTab.classList.remove("active-tab");

    selectSourceBtn.textContent = "1. Select Input Folder to Encrypt";
    selectOutputBtn.textContent = "2. Select Vault Output Folder";
    keyModeWrapper.style.display = "flex";
    updateKeyModeUI();

    settingsGroup.style.display = "grid";
    confirmGroup.style.display = "flex";
    confirmPinInput.required = true;
    actionBtn.textContent = "Lock Vault";
    actionBtn.style.backgroundColor = "var(--accent)";
  } else {
    modeDecryptTab.classList.add("active-tab");
    modeEncryptTab.classList.remove("active-tab");

    selectSourceBtn.textContent = "1. Select Vault File (.obv)";
    selectOutputBtn.textContent = "2. Select Extraction Output Folder";
    keyModeWrapper.style.display = "none";
    selectKeyBtn.textContent = "3. Select Private Key File (.obk)";

    settingsGroup.style.display = "none";
    advancedOptions.style.display = "none";
    confirmGroup.style.display = "none";
    confirmPinInput.required = false;
    strengthContainer.style.display = "none";
    strengthText.style.display = "none";

    actionBtn.textContent = "Unlock Vault";
    actionBtn.style.backgroundColor = "#28a745";
  }
}

// --- Key Handling Mode Switcher (New Keypair vs Existing .obp) ---
keyModeSelect.addEventListener("change", () => {
  keyPath = null;
  keyDisplay.textContent = "No key location selected";
  updateKeyModeUI();
  runPreFlightSpaceCheck();
});

function updateKeyModeUI() {
  if (keyModeSelect.value === "existing_obp") {
    selectKeyBtn.textContent = "3. Select Public Sealing Key (.obp)";
    kemAlgoGroup.style.display = "none"; // KEM is determined by the .obp file
    advancedOptions.style.display = "none"; // Duress block lives inside .obk
  } else {
    selectKeyBtn.textContent = "3. Select Folder to Save Keys (.obk / .obp)";
    kemAlgoGroup.style.display = "flex";
    advancedOptions.style.display = "block";
  }
}

// --- Path Selector Button Handlers ---
selectSourceBtn.addEventListener("click", async () => {
  if (currentMode === "ENCRYPT") {
    const selected = await open({
      multiple: false,
      directory: true,
      title: "Select Input Folder to Encrypt",
    });
    if (selected) {
      targetPath = selected;
      targetDisplay.textContent = targetPath;
      await runPreFlightSpaceCheck();
    }
  } else {
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select Vault (.obv) to Decrypt",
      filters: [{ name: "Ombracrypt Vault", extensions: ["obv"] }],
    });
    if (selected) {
      targetPath = selected;
      targetDisplay.textContent = targetPath;
      await runPreFlightSpaceCheck();
    }
  }
});

selectOutputBtn.addEventListener("click", async () => {
  const selected = await open({
    multiple: false,
    directory: true,
    title:
      currentMode === "ENCRYPT"
        ? "Select Folder to Save Encrypted Vault (.obv)"
        : "Select Destination Folder for Extracted Files",
  });
  if (selected) {
    outputDir = selected;
    outputDisplay.textContent = outputDir;
    await runPreFlightSpaceCheck();
  }
});

selectKeyBtn.addEventListener("click", async () => {
  if (currentMode === "ENCRYPT" && keyModeSelect.value === "generate") {
    const selected = await open({
      multiple: false,
      directory: true,
      title: "Select Folder to Save Generated Keys (.obk & .obp)",
    });
    if (selected) {
      keyPath = selected;
      keyDisplay.textContent = keyPath;
      await runPreFlightSpaceCheck();
    }
  } else if (currentMode === "ENCRYPT" && keyModeSelect.value === "existing_obp") {
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select Public Sealing Key (.obp)",
      filters: [{ name: "Ombracrypt Public Key", extensions: ["obp"] }],
    });
    if (selected) {
      keyPath = selected;
      keyDisplay.textContent = keyPath;
      await runPreFlightSpaceCheck();
    }
  } else {
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select Private Key (.obk)",
      filters: [{ name: "Ombracrypt Private Key", extensions: ["obk"] }],
    });
    if (selected) {
      keyPath = selected;
      keyDisplay.textContent = keyPath;
      await runPreFlightSpaceCheck();
    }
  }
});

// --- Instant Pre-Flight Disk Space & Collision Check ---
async function runPreFlightSpaceCheck() {
  if (!targetPath || !outputDir) {
    spaceTelemetryBox.style.display = "none";
    storageCheckPassed = false;
    return;
  }

  spaceTelemetryBox.style.display = "block";
  spaceTelemetryText.textContent = "Assessing storage & path safety...";
  spaceTelemetryBox.className = "telemetry-box";

  try {
    const report = await invoke("inspect_path_space", {
      mode: currentMode,
      sourcePath: targetPath,
      outputDir: outputDir,
      keyDirOrFile: keyPath,
    });

    if (!report.sufficient) {
      spaceTelemetryText.textContent = `Insufficient Space! ${report.summary}`;
      spaceTelemetryBox.className = "telemetry-box telemetry-error";
      actionBtn.disabled = true;
      storageCheckPassed = false;
    } else if (report.conflict_error) {
      spaceTelemetryText.textContent = `Path Conflict: ${report.conflict_error}`;
      spaceTelemetryBox.className = "telemetry-box telemetry-error";
      actionBtn.disabled = true;
      storageCheckPassed = false;
    } else {
      spaceTelemetryText.textContent = `Storage Verified ✓ (${report.summary})`;
      spaceTelemetryBox.className = "telemetry-box telemetry-ok";
      actionBtn.disabled = false;
      storageCheckPassed = true;
    }
  } catch (err) {
    spaceTelemetryText.textContent = `Check Error: ${err}`;
    spaceTelemetryBox.className = "telemetry-box telemetry-error";
    actionBtn.disabled = true;
    storageCheckPassed = false;
  }
}

// --- Real-time Password Validation Logic ---
mainPinInput.addEventListener("input", () => {
  if (currentMode === "ENCRYPT") {
    checkPasswordStrength(mainPinInput.value);
    checkPasswordMatch();
    checkDeceptionValidation();
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

function checkDeceptionValidation() {
  const masterPin = mainPinInput.value;
  const d1 = deceptionInput.value;
  const d2 = confirmDeceptionInput.value;

  if (!d1 && !d2) {
    deceptionMatchMsg.textContent = "";
    return;
  }

  if (d1 && masterPin && d1 === masterPin) {
    deceptionMatchMsg.textContent = "Passcode cannot match Master Password ✗";
    deceptionMatchMsg.style.color = "#ff4444";
    return;
  }

  if (!d2) {
    deceptionMatchMsg.textContent = "";
    return;
  }

  if (d1 === d2) {
    deceptionMatchMsg.textContent = "Deception passcodes match ✓";
    deceptionMatchMsg.style.color = "#00C851";
  } else {
    deceptionMatchMsg.textContent = "Deception passcodes do not match ✗";
    deceptionMatchMsg.style.color = "#ff4444";
  }
}

deceptionInput.addEventListener("input", checkDeceptionValidation);
confirmDeceptionInput.addEventListener("input", checkDeceptionValidation);

// --- Bridge to Rust Backend & In-Memory Streaming ETA Logic ---
listen("crypto-progress", (event) => {
  const currentProgress = event.payload;

  progressContainer.style.display = "block";
  progressBar.style.width = currentProgress + "%";
  if (progressPercent) progressPercent.textContent = currentProgress + "%";

  const streamStartThreshold = currentMode === "ENCRYPT" ? 30 : 40;

  if (currentProgress < streamStartThreshold) {
    if (progressEta) progressEta.textContent = "Deriving Argon2id & ML-KEM keys...";
  } else if (currentProgress === streamStartThreshold) {
    streamStartTime = Date.now();
    if (progressEta) progressEta.textContent = "Streaming in-memory chunks...";
  } else if (currentProgress >= 100) {
    if (progressEta) progressEta.textContent = "Completed!";
  } else {
    const elapsedMs = Math.max(1, Date.now() - streamStartTime);
    const phaseProgress = Math.max(1, currentProgress - streamStartThreshold);
    const msPerPercent = elapsedMs / phaseProgress;
    const remainingPercents = 100 - currentProgress;
    const remainingMs = msPerPercent * remainingPercents;

    const totalSeconds = Math.floor(remainingMs / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = (totalSeconds % 60).toString().padStart(2, "0");

    if (progressEta) progressEta.textContent = `ETA: ${minutes}m ${seconds}s remaining`;
  }
});

// --- Form Submission ---
const cryptoForm = document.getElementById("crypto-form");

cryptoForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  if (!targetPath || !outputDir || !keyPath) {
    statusMsg.textContent = "Please select Source, Output Folder, and Key Location before proceeding.";
    statusMsg.style.color = "#ff4444";
    return;
  }

  await runPreFlightSpaceCheck();
  if (!storageCheckPassed) {
    statusMsg.textContent = "Cannot proceed: Please resolve storage or path conflict errors above.";
    statusMsg.style.color = "#ff4444";
    return;
  }

  const mainPin = mainPinInput.value;
  const confirmPin = confirmPinInput.value;
  const deceptionPasscode = deceptionInput.value;
  const confirmDeception = confirmDeceptionInput.value;

  if (currentMode === "ENCRYPT") {
    if (mainPin !== confirmPin) {
      statusMsg.textContent = "Error: Master Passwords do not match.";
      statusMsg.style.color = "#ff4444";
      return;
    }

    if (keyModeSelect.value === "generate" && deceptionPasscode) {
      if (deceptionPasscode === mainPin) {
        statusMsg.textContent = "Error: Deception passcode cannot match Master Password.";
        statusMsg.style.color = "#ff4444";
        return;
      }
      if (deceptionPasscode !== confirmDeception) {
        statusMsg.textContent = "Error: Deception passcodes do not match.";
        statusMsg.style.color = "#ff4444";
        return;
      }
    }
  }

  const cipher = document.getElementById("cipher-algo").value;
  const kem = document.getElementById("kem-algo").value;
  const useExistingPublicKey =
    currentMode === "ENCRYPT" && keyModeSelect.value === "existing_obp";

  progressContainer.style.display = "block";
  progressBar.style.width = "0%";
  if (progressPercent) progressPercent.textContent = "0%";
  if (progressEta) progressEta.textContent = "Initializing pipeline...";

  statusMsg.textContent =
    "Executing in-memory cryptographic streaming. Do not close the application.";
  statusMsg.style.color = "var(--accent)";
  actionBtn.disabled = true;

  try {
    const response = await invoke("process_cryptography", {
      mode: currentMode,
      targetPath: targetPath,
      outputDir: outputDir,
      keyPath: keyPath,
      useExistingPublicKey: useExistingPublicKey,
      cipher: cipher,
      kem: kem,
      mainPin: mainPin,
      deceptionPasscode: deceptionPasscode,
    });

    statusMsg.textContent = response;
    statusMsg.style.color = "#28a745";
  } catch (error) {
    statusMsg.textContent = "Error: " + error;
    statusMsg.style.color = "#ff4444";
  } finally {
    mainPinInput.value = "";
    confirmPinInput.value = "";
    deceptionInput.value = "";
    confirmDeceptionInput.value = "";

    matchMsg.textContent = "";
    deceptionMatchMsg.textContent = "";
    strengthContainer.style.display = "none";
    strengthText.style.display = "none";
    actionBtn.disabled = false;
  }
});