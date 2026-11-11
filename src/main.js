const { open } = window.__TAURI_PLUGIN_DIALOG__;
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// --- Mode Tab Elements ---
const modeEncryptTab = document.getElementById("mode-encrypt-tab");
const modeDecryptTab = document.getElementById("mode-decrypt-tab");

// --- Path Selection Elements ---
const sourceLocationLabel = document.getElementById("source-location-label");
const selectSourceBtn = document.getElementById("select-source-btn");
const targetDisplay = document.getElementById("target-path-display");

const outputDestLabel = document.getElementById("output-dest-label");
const selectOutputBtn = document.getElementById("select-output-btn");
const outputDisplay = document.getElementById("output-path-display");

const keyModeWrapper = document.getElementById("key-mode-wrapper");
const keyModeSelect = document.getElementById("key-mode-select");
const publicSealingBanner = document.getElementById("public-sealing-banner");
const keyDestSubblock = document.getElementById("key-dest-subblock");
const keyDestLabel = document.getElementById("key-dest-label");
const selectKeyBtn = document.getElementById("select-key-btn");
const keyDisplay = document.getElementById("key-path-display");

const spaceTelemetryBox = document.getElementById("space-telemetry-box");
const spaceTelemetryText = document.getElementById("space-telemetry-text");

// --- Settings & Action Elements ---
const settingsGroup = document.getElementById("settings-group");
const cipherAlgoSelect = document.getElementById("cipher-algo");
const kemAlgoSelect = document.getElementById("kem-algo");
const kemAlgoGroup = document.getElementById("kem-algo-group");
const advancedOptions = document.getElementById("advanced-options");
const actionBtn = document.getElementById("action-btn");
const abortBtn = document.getElementById("abort-btn");

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

// --- Progress & Phase Elements ---
const progressContainer = document.getElementById("progress-container");
const progressBar = document.getElementById("progress-bar");
const progressPercent = document.getElementById("progress-percent");
const progressEta = document.getElementById("progress-eta");
const statusMsg = document.getElementById("status-msg");

const phaseNode1 = document.getElementById("phase-node-1");
const phaseNode2 = document.getElementById("phase-node-2");
const phaseNode3 = document.getElementById("phase-node-3");
const phaseLine1 = document.getElementById("phase-line-1");
const phaseLine2 = document.getElementById("phase-line-2");

// --- Staging Hygiene / Maintenance Modal Elements ---
const openMaintenanceBtn = document.getElementById("open-maintenance-btn");
const closeMaintenanceBtn = document.getElementById("close-maintenance-btn");
const maintenanceModal = document.getElementById("maintenance-modal");
const maintenanceDirsList = document.getElementById("maintenance-dirs-list");
const executeMaintenanceBtn = document.getElementById("execute-maintenance-btn");
const maintenanceReportBox = document.getElementById("maintenance-report-box");
const maintenanceReportSummary = document.getElementById("maintenance-report-summary");

// --- Application State ---
let currentMode = "ENCRYPT"; // "ENCRYPT" or "DECRYPT"
let targetPath = null;
let outputDir = null;
let keyPath = null;
let storageCheckPassed = false;
let streamStartTime = 0;
let isOperationRunning = false;
const hideTimeouts = new Map();

// --- Mode Switching Logic ---
modeEncryptTab.addEventListener("click", () => switchMode("ENCRYPT"));
modeDecryptTab.addEventListener("click", () => switchMode("DECRYPT"));

function setFormControlsDisabled(disabled) {
  selectSourceBtn.disabled = disabled;
  selectOutputBtn.disabled = disabled;
  selectKeyBtn.disabled = disabled;
  keyModeSelect.disabled = disabled;
  cipherAlgoSelect.disabled = disabled;
  kemAlgoSelect.disabled = disabled;
  mainPinInput.disabled = disabled;
  confirmPinInput.disabled = disabled;
  deceptionInput.disabled = disabled;
  confirmDeceptionInput.disabled = disabled;
  modeEncryptTab.disabled = disabled;
  modeDecryptTab.disabled = disabled;
  openMaintenanceBtn.disabled = disabled;
  document.querySelectorAll(".eye-toggle-btn").forEach((btn) => (btn.disabled = disabled));
}

function updateExecutionUI() {
  if (isOperationRunning) {
    actionBtn.disabled = true;
    abortBtn.style.display = "block";
    abortBtn.disabled = false;
    setFormControlsDisabled(true);
  } else {
    actionBtn.disabled = false;
    abortBtn.style.display = "none";
    setFormControlsDisabled(false);
  }
}

function switchMode(newMode) {
  if (isOperationRunning) return;

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

  resetProgressPhases();
  progressContainer.style.display = "none";
  progressBar.style.width = "0%";
  if (progressPercent) progressPercent.textContent = "0%";
  if (progressEta) progressEta.textContent = "";

  updateExecutionUI();

  if (currentMode === "ENCRYPT") {
    modeEncryptTab.classList.add("active-tab");
    modeDecryptTab.classList.remove("active-tab");

    if (sourceLocationLabel) sourceLocationLabel.textContent = "SOURCE LOCATION";
    selectSourceBtn.querySelector(".btn-text").textContent = "Select Input Folder to Encrypt";

    if (outputDestLabel) outputDestLabel.textContent = "VAULT DESTINATION (.OBV)";
    selectOutputBtn.querySelector(".btn-text").textContent = "Select Vault Output Folder";

    keyModeWrapper.style.display = "flex";
    updateKeyModeUI();

    settingsGroup.style.display = "grid";
    confirmGroup.style.display = "flex";
    confirmPinInput.required = true;
    actionBtn.textContent = "Lock Vault";
    actionBtn.style.background = "linear-gradient(135deg, #0284c7 0%, #00f0ff 100%)";
    actionBtn.style.color = "#020817";
  } else {
    modeDecryptTab.classList.add("active-tab");
    modeEncryptTab.classList.remove("active-tab");

    if (sourceLocationLabel) sourceLocationLabel.textContent = "ENCRYPTED VAULT FILE";
    selectSourceBtn.querySelector(".btn-text").textContent = "Select Vault File (.obv)";

    if (outputDestLabel) outputDestLabel.textContent = "EXTRACTION DESTINATION FOLDER";
    selectOutputBtn.querySelector(".btn-text").textContent = "Select Extraction Output Folder";

    keyModeWrapper.style.display = "none";
    publicSealingBanner.style.display = "none";
    keyDestSubblock.style.display = "block";
    keyDestLabel.textContent = "PRIVATE KEY LOCATION (.OBK)";
    selectKeyBtn.querySelector(".btn-text").textContent = "Select Private Key (.obk)";

    settingsGroup.style.display = "none";
    advancedOptions.style.display = "none";
    confirmGroup.style.display = "none";
    confirmPinInput.required = false;
    strengthContainer.style.display = "none";
    strengthText.style.display = "none";

    actionBtn.textContent = "Unlock Vault";
    actionBtn.style.background = "linear-gradient(135deg, #059669 0%, #34d399 100%)";
    actionBtn.style.color = "#020817";
  }
}

// --- Key Handling Mode Switcher ---
keyModeSelect.addEventListener("change", () => {
  keyPath = null;
  keyDisplay.textContent = "No key location selected";
  updateKeyModeUI();
  runPreFlightSpaceCheck();
});

function updateKeyModeUI() {
  if (keyModeSelect.value === "existing_obp") {
    publicSealingBanner.style.display = "flex";
    keyDestLabel.textContent = "PUBLIC SEALING KEY (.OBP)";
    selectKeyBtn.querySelector(".btn-text").textContent = "Select Public Key (.obp)";
    kemAlgoGroup.style.display = "none";
    advancedOptions.style.display = "none";
  } else {
    publicSealingBanner.style.display = "none";
    keyDestLabel.textContent = "KEY DESTINATION (.OBK / .OBP)";
    selectKeyBtn.querySelector(".btn-text").textContent = "Select Folder to Save Keys (.obk / .obp)";
    kemAlgoGroup.style.display = "flex";
    advancedOptions.style.display = "block";
  }
}

// --- Path Selector Handlers ---
selectSourceBtn.addEventListener("click", async () => {
  if (isOperationRunning) return;
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
  if (isOperationRunning) return;
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
  if (isOperationRunning) return;
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

// Click-to-copy helper for path readouts
[targetDisplay, outputDisplay, keyDisplay].forEach((display) => {
  display.addEventListener("click", () => {
    if (display.textContent && !display.textContent.startsWith("No ")) {
      navigator.clipboard.writeText(display.textContent);
      const original = display.textContent;
      display.textContent = "Copied to clipboard!";
      setTimeout(() => (display.textContent = original), 1400);
    }
  });
});

// --- Pre-Flight Disk Space & Collision Check ---
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
      const fpBadge = report.key_fingerprint
        ? ` | Key ID: ${report.key_fingerprint}`
        : "";
      spaceTelemetryText.textContent = `Storage Verified ✓ (${report.summary}${fpBadge})`;
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

// --- Abort Active Operation Button ---
abortBtn.addEventListener("click", async () => {
  if (!isOperationRunning) return;
  try {
    statusMsg.textContent = "Canceling operation and purging staging artifacts...";
    statusMsg.style.color = "#f87171";
    abortBtn.disabled = true;
    await invoke("cancel_current_operation");
  } catch (err) {
    statusMsg.textContent = "Cancellation error: " + err;
    statusMsg.style.color = "#f87171";
  }
});

// --- Staging Hygiene / Maintenance Modal Handlers ---
openMaintenanceBtn.addEventListener("click", () => {
  if (isOperationRunning) return;
  const dirs = getActiveTargetDirs();
  maintenanceDirsList.innerHTML = "";
  if (dirs.length === 0) {
    maintenanceDirsList.innerHTML = "<li>No active workspace folders selected yet.</li>";
    executeMaintenanceBtn.disabled = true;
  } else {
    dirs.forEach((d) => {
      const li = document.createElement("li");
      li.textContent = d;
      maintenanceDirsList.appendChild(li);
    });
    executeMaintenanceBtn.disabled = false;
  }
  maintenanceReportBox.style.display = "none";
  maintenanceModal.style.display = "flex";
});

closeMaintenanceBtn.addEventListener("click", () => {
  maintenanceModal.style.display = "none";
});

window.addEventListener("click", (e) => {
  if (e.target === maintenanceModal) {
    maintenanceModal.style.display = "none";
  }
});

function getActiveTargetDirs() {
  const targetDirs = [];
  if (outputDir) targetDirs.push(outputDir);
  if (keyPath) {
    const pathStr = keyPath.toString();
    if (pathStr.endsWith(".obk") || pathStr.endsWith(".obp")) {
      const lastSlash = Math.max(pathStr.lastIndexOf("/"), pathStr.lastIndexOf("\\"));
      if (lastSlash > 0) targetDirs.push(pathStr.substring(0, lastSlash));
    } else {
      targetDirs.push(keyPath);
    }
  }
  return [...new Set(targetDirs)];
}

executeMaintenanceBtn.addEventListener("click", async () => {
  const dirs = getActiveTargetDirs();
  if (dirs.length === 0) return;

  executeMaintenanceBtn.disabled = true;
  executeMaintenanceBtn.textContent = "Scanning...";
  try {
    const res = await invoke("clean_staging_artifacts", { paths: dirs });
    maintenanceReportBox.style.display = "block";
    maintenanceReportSummary.textContent = res;
    await runPreFlightSpaceCheck();
  } catch (err) {
    maintenanceReportBox.style.display = "block";
    maintenanceReportSummary.textContent = "Cleanup Notice: " + err;
  } finally {
    executeMaintenanceBtn.disabled = false;
    executeMaintenanceBtn.textContent = "Run Cleanup Sweep";
  }
});

// --- Password Visibility Toggles with 8s Auto-Mask ---
document.querySelectorAll(".eye-toggle-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.getAttribute("data-target");
    const input = document.getElementById(targetId);
    if (!input || input.disabled) return;

    if (input.type === "password") {
      input.type = "text";
      btn.innerHTML = "&#128064;";

      if (hideTimeouts.has(targetId)) {
        clearTimeout(hideTimeouts.get(targetId));
      }

      const timeoutId = setTimeout(() => {
        input.type = "password";
        btn.innerHTML = "&#128065;";
        hideTimeouts.delete(targetId);
      }, 8000);

      hideTimeouts.set(targetId, timeoutId);
    } else {
      input.type = "password";
      btn.innerHTML = "&#128065;";
      if (hideTimeouts.has(targetId)) {
        clearTimeout(hideTimeouts.get(targetId));
        hideTimeouts.delete(targetId);
      }
    }
  });
});

// --- Real-time Password Strength & Match Validation ---
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
    strengthBar.style.backgroundColor = "#f87171";
    strengthText.textContent = "Strength: Weak";
    strengthText.style.color = "#f87171";
  } else if (strength === 3 || strength === 4) {
    strengthBar.style.width = "66%";
    strengthBar.style.backgroundColor = "#fbbf24";
    strengthText.textContent = "Strength: Moderate";
    strengthText.style.color = "#fbbf24";
  } else {
    strengthBar.style.width = "100%";
    strengthBar.style.backgroundColor = "#00f0ff";
    strengthText.textContent = "Strength: Spectral Shield (Strong)";
    strengthText.style.color = "#38bdf8";
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
    matchMsg.style.color = "#38bdf8";
  } else {
    matchMsg.textContent = "Passwords do not match ✗";
    matchMsg.style.color = "#f87171";
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
    deceptionMatchMsg.style.color = "#f87171";
    return;
  }

  if (!d2) {
    deceptionMatchMsg.textContent = "";
    return;
  }

  if (d1 === d2) {
    deceptionMatchMsg.textContent = "Deception passcodes match ✓";
    deceptionMatchMsg.style.color = "#38bdf8";
  } else {
    deceptionMatchMsg.textContent = "Deception passcodes do not match ✗";
    deceptionMatchMsg.style.color = "#f87171";
  }
}

deceptionInput.addEventListener("input", checkDeceptionValidation);
confirmDeceptionInput.addEventListener("input", checkDeceptionValidation);

// --- Phased Progress & Telemetry Tracking ---
function resetProgressPhases() {
  phaseNode1.className = "phase-node active";
  phaseNode2.className = "phase-node";
  phaseNode3.className = "phase-node";
  phaseLine1.className = "phase-line";
  phaseLine2.className = "phase-line";
}

listen("crypto-progress", (event) => {
  const currentProgress = event.payload;

  progressContainer.style.display = "block";
  progressBar.style.width = currentProgress + "%";
  if (progressPercent) progressPercent.textContent = currentProgress + "%";

  const streamStartThreshold = currentMode === "ENCRYPT" ? 30 : 40;

  if (currentProgress < streamStartThreshold) {
    phaseNode1.className = "phase-node active";
    phaseLine1.className = "phase-line";
    phaseNode2.className = "phase-node";
    if (progressEta) progressEta.textContent = "Phase 1: Synthesizing keys & KEM encapsulation...";
  } else if (currentProgress >= streamStartThreshold && currentProgress < 98) {
    if (streamStartTime === 0) streamStartTime = Date.now();
    phaseNode1.className = "phase-node complete";
    phaseLine1.className = "phase-line active";
    phaseNode2.className = "phase-node active";

    const elapsedMs = Math.max(1, Date.now() - streamStartTime);
    const phaseProgress = Math.max(1, currentProgress - streamStartThreshold);
    const msPerPercent = elapsedMs / phaseProgress;
    const remainingPercents = 100 - currentProgress;
    const remainingMs = msPerPercent * remainingPercents;

    const totalSeconds = Math.floor(remainingMs / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = (totalSeconds % 60).toString().padStart(2, "0");

    if (progressEta) progressEta.textContent = `Phase 2: Streaming AEAD (~${minutes}m ${seconds}s left)`;
  } else if (currentProgress >= 98 && currentProgress < 100) {
    phaseNode2.className = "phase-node complete";
    phaseLine2.className = "phase-line active";
    phaseNode3.className = "phase-node active";
    if (progressEta) progressEta.textContent = "Phase 3: Verifying tags & committing atomic promotion...";
  } else {
    phaseNode3.className = "phase-node complete";
    if (progressEta) progressEta.textContent = "Completed!";
  }
});

// --- Form Submission ---
const cryptoForm = document.getElementById("crypto-form");

cryptoForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  if (!targetPath || !outputDir || !keyPath) {
    statusMsg.textContent = "Please select Source, Output Folder, and Key Location before proceeding.";
    statusMsg.style.color = "#f87171";
    return;
  }

  await runPreFlightSpaceCheck();
  if (!storageCheckPassed) {
    statusMsg.textContent = "Cannot proceed: Please resolve storage or path conflict errors above.";
    statusMsg.style.color = "#f87171";
    return;
  }

  const mainPin = mainPinInput.value;
  const confirmPin = confirmPinInput.value;
  const deceptionPasscode = deceptionInput.value;
  const confirmDeception = confirmDeceptionInput.value;

  if (currentMode === "ENCRYPT") {
    if (mainPin !== confirmPin) {
      statusMsg.textContent = "Error: Master Passwords do not match.";
      statusMsg.style.color = "#f87171";
      return;
    }

    if (keyModeSelect.value === "generate" && deceptionPasscode) {
      if (deceptionPasscode === mainPin) {
        statusMsg.textContent = "Error: Deception passcode cannot match Master Password.";
        statusMsg.style.color = "#f87171";
        return;
      }
      if (deceptionPasscode !== confirmDeception) {
        statusMsg.textContent = "Error: Deception passcodes do not match.";
        statusMsg.style.color = "#f87171";
        return;
      }
    }
  }

  const cipher = cipherAlgoSelect.value;
  const kem = kemAlgoSelect.value;
  const useExistingPublicKey =
    currentMode === "ENCRYPT" && keyModeSelect.value === "existing_obp";

  isOperationRunning = true;
  streamStartTime = 0;
  updateExecutionUI();
  resetProgressPhases();

  progressContainer.style.display = "block";
  progressBar.style.width = "0%";
  if (progressPercent) progressPercent.textContent = "0%";
  if (progressEta) progressEta.textContent = "Phase 1: Initializing pipeline...";

  statusMsg.textContent = "Executing in-memory cryptographic streaming. Do not close the application.";
  statusMsg.style.color = "var(--patronus-cyan)";

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
    statusMsg.style.color = "#38bdf8";
  } catch (error) {
    statusMsg.textContent = "Error: " + error;
    statusMsg.style.color = "#f87171";
    progressContainer.style.display = "none";
  } finally {
    isOperationRunning = false;
    updateExecutionUI();

    mainPinInput.value = "";
    confirmPinInput.value = "";
    deceptionInput.value = "";
    confirmDeceptionInput.value = "";

    matchMsg.textContent = "";
    deceptionMatchMsg.textContent = "";
    strengthContainer.style.display = "none";
    strengthText.style.display = "none";
  }
});