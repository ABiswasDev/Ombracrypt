# Ombracrypt Quick Start Guide

This guide will walk you through the fundamental steps of securing your data using Ombracrypt's post-quantum encryption engine. 

## How to Encrypt Your Data

**Step 1: Algorithm & Password Configuration**
Launch the Ombracrypt application. Select your preferred **Cipher Algorithm** (e.g., AES-256-GCM) and **KEM Algorithm** (e.g., Cypherpunk Max) from the dropdown menus. Enter a strong, memorable master password. If your threat model requires it, you may also configure a **Panic Password** under the Advanced Security Options.

<p align="center">
  <img src="../images/enc1.png" alt="Ombracrypt Algorithm Configuration" width="450">
</p>

**Step 2: Target Selection**
Click the **Encrypt Folder** button. This will open your native system file explorer. Navigate to and select the specific directory containing the data you wish to encrypt. In this example, we are selecting a directory named `vault` located inside a `Demo` folder.

<p align="center">
  <img src="../images/enc2.png" alt="Selecting the Target Directory" width="600">
</p>

**Step 3: Path Verification & Execution**
Once selected, the application will display the target encryption path (e.g., `/Demo/vault`). Verify this path carefully to ensure you are encrypting the correct data—everything inside this selected folder will be secured. Click the **Lock Vault** button to begin. A progress bar will appear at the bottom of the interface; execution time will vary based on your payload size and the selected cryptographic algorithms.

<p align="center">
  <img src="../images/enc3.png" alt="Verifying Path and Locking Vault" width="450">
</p>

**Step 4: Successful Completion**
Upon completion, the progress bar will finalize, and a green success message will appear at the bottom of the application confirming: *"Operation Successful: Vault securely locked (.obv) and Quantum Key (.obk) generated."*

<p align="center">
  <img src="../images/enc4.png" alt="Encryption Successful" width="600">
</p>

**Step 5: Output & Key Separation**
Open your system file explorer and navigate to the directory where your original folder was located. You will now see two newly generated files: your encrypted vault (`vault.obv`) and your cryptographic key (`vault.obk`). 

**Crucial Security Step:** Your vault (`.obv`) is now quantum-secure and can be safely uploaded to the cloud or transmitted over untrusted networks. However, you **must** move the `.obk` key file to a physically and logically separate, highly secure location (such as an offline USB flash drive). Without *both* the `.obk` file and your master password, the vault cannot be decrypted by anyone.

<p align="center">
  <img src="../images/enc5.png" alt="Generated Vault and Key Files" width="600">
</p>