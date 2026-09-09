# Ombracrypt Quick Start Guide

This guide will walk you through the fundamental steps of securing your data using Ombracrypt's post-quantum encryption engine. 

## How to Encrypt Your Data

**Step 1: Algorithm & Password Configuration**
Launch the Ombracrypt application. Select your preferred **Cipher Algorithm** (e.g., AES-256-GCM) and **KEM Algorithm** (e.g., Cypherpunk Max) from the dropdown menus. Enter a strong, memorable master password. If your threat model requires it, you may also configure a **Deception Passcode** under the Advanced Security Options.

<p align="center">
  <img src="../images/enc1.png" alt="Ombracrypt Algorithm Configuration" width="450">
</p>

**Step 2: Target Selection**
Click the **Encrypt Folder** button. This will open your native system file explorer. Navigate to and select the specific directory containing the data you wish to encrypt. In this example, we are selecting a directory named `My Data` located on an external drive.

<p align="center">
  <img src="../images/enc2.png" alt="Selecting the Target Directory" width="600">
</p>

**Step 3: Path Verification & Execution**
the application will display the target encryption path (e.g., `/media/abby/E8DF-98B9/My data`). Verify this path carefully to ensure you are encrypting the correct data—everything inside this selected folder will be secured. Click the **Lock Vault** button to begin. A progress bar will appear at the bottom of the interface; execution time will vary based on your payload size and the selected cryptographic algorithms.

<p align="center">
  <img src="../images/enc3.png" alt="Verifying Path and Locking Vault" width="450">
</p>

**Step 4: Successful Completion**
Upon completion, the progress bar will finalize, and a green success message will appear at the bottom of the application confirming: *"Operation Successful: Vault securely locked (.obv) and Quantum Key (.obk) generated."*

<p align="center">
  <img src="../images/enc4.png" alt="Encryption Successful" width="450">
</p>

**Step 5: Output & Key Separation**
Open your system file explorer and navigate to the directory where your original folder was located. You will now see two newly generated files: your encrypted vault (`My data.obv`) and your cryptographic key (`My data.obk`). 

**Crucial Security Step:** Your vault (`.obv`) is now quantum-secure and can be safely uploaded to the cloud or transmitted over untrusted networks. However, you **must** move the `.obk` key file to a physically and logically separate, highly secure location (such as an offline USB flash drive). Without *both* the `.obk` file and your master password, the vault cannot be decrypted by anyone.

## How to Decrypt Your Data

**Step 1: Selecting Your Assets**
Launch the Ombracrypt application and select the **Decrypt Vault** option. You will need to provide both your encrypted vault file (`.obv`) and your mathematically linked Ombracrypt Quantum Key (`.obk`). 

**Step 2: Path Verification**
Check the file paths displayed in the upper section of the decryption module. Confirm that the correct `.obv` and `.obk` files are loaded before proceeding.

**Step 3: Execution and Output**
Enter your standard master password and execute the decryption. The engine will process the vault and output your fully decrypted original folder to the exact same directory where your `.obv` vault file is currently located.

<div align="center">
  <img src="../images/dec1.png" alt="Ombracrypt Decryption Interface" width="450">
</div>

> **⚠️ Critical Feature: Deception Passcode (Duress Code)**
>
> The Deception Passcode is a specialized cryptographic zeroization failsafe designed for extreme threat models, specifically for situations where you are under physical coercion and being forced to unlock your vault. Because this mechanism is destructive, it is vital to understand exactly how it operates:
>
> * **The Scenario:** If a hostile actor forces you to decrypt your data, you will launch the Ombracrypt decryption interface exactly as you normally would.
> * **The Action:** When prompted for your credentials, you will input your pre-configured **Deception Passcode** *instead* of your actual Master Password.
> * **The Execution:** The application will intentionally throw a "password mismatch" error to deceive the intruder into thinking a simple typo occurred. Simultaneously in the background, the engine will instantly tamper with the `.obk` (Quantum Key) file. It permanently scrambles the internal cryptographic key material while leaving the file's external metadata and structure completely intact.
> * **The Result:** Because Ombracrypt utilizes a split-key architecture, the zeroization of the `.obk` payload instantly breaks the cryptographic chain. To the attacker, the key file still appears to be physically present, but the `.obv` (Encrypted Vault) file is now permanently mathematically inaccessible to everyone—including you and the attacker.
> 
> **Important:** This action is strictly irreversible. Activating the Deception Passcode permanently neutralizes the threat by destroying the internal keys to your data, so it should only be triggered in absolute emergencies.