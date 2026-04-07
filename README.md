# S431F-Blockchain
# 🏥 Medical Chain – Encrypted Healthcare DApp

A blockchain-based healthcare system that enables secure storage and sharing of patient data using end-to-end encryption.

This system allows patients and doctors to interact through smart contracts, ensuring:
- Privacy (encrypted medical data)
- Trust (on-chain verification)
- Controlled access (doctor authorization)

---

# 🚀 Features

## 👤 Patient
- Register encrypted personal profile
- Update profile securely
- Authorize / revoke doctor access
- Create appointments with doctors
- View medical records (decrypted locally)
- View allergy records
- Manage token balance (coins)

## 👨‍⚕️ Doctor
- Register doctor profile
- View authorized patients
- Approve / reject appointments
- Add medical records (encrypted)
- Add allergy records (encrypted)
- Automatically complete appointment + settlement

## 🔐 Security
- End-to-end encryption using MetaMask public key
- Data stored on-chain is encrypted
- Only authorized parties can decrypt

---

# 🧱 System Architecture

## Smart Contracts
- `PatientRegistry`
- `DoctorRegistry`

## Frontend
- HTML + CSS dashboard
- `app.js` handles:
  - MetaMask interaction
  - Encryption / decryption
  - Contract calls

## Encryption Stack
- MetaMask `eth_getEncryptionPublicKey`
- `eth-sig-util`
- `tweetnacl`

---

# 🔄 How the Program Works (Workflow)

Before using the app, both the doctor and patient must register separately. Then follow the phases below in order.

---

## Phase 1 – Registration (one-time setup)

**Doctor (do this first):**
1. Open the app and connect MetaMask
2. Select the **Doctor** role
3. Fill in name, license, hospital, specialties, phone
4. Click **Register as Doctor** – this writes your profile to the blockchain
5. Set your **encryption public key** – patients use this to encrypt data for you

**Patient:**
1. Connect MetaMask and select the **Patient** role
2. Fill in personal details (name, ID, birthday, weight, height, etc.)
3. Enter the doctor's wallet address and the doctor's encryption public key
4. Click **Register as Patient** – your data is encrypted locally before going on-chain

---

## Phase 2 – Authorization and Coins (must be done before appointment)

These two steps can be done in either order, but both must be completed before the appointment can be settled.

**Patient authorizes the doctor:**
- Go to Doctor Authorization
- Enter the doctor's wallet address, set to `true`
- Click **Apply authorization**
- Without this, the doctor cannot access any of your records

**Grant initial coins to the patient:**
- Go to Appointments & Coins
- Enter the patient address and an amount
- Click **Grant Initial Coins**
- Without coins, the final settlement will fail

---

## Phase 3 – Appointment

**Patient creates an appointment:**
1. Go to Appointments & Coins
2. Enter the doctor's address, date/time, fee, and reason
3. Click **Create appointment**
4. Status becomes: `Requested`

**Doctor responds:**
1. Click **Load appointment IDs** to see pending appointments
2. Enter the appointment ID
3. Click **Approve** or **Reject**
4. Status becomes: `Approved` or `Rejected`

---

## Phase 4 – Complete the Appointment (settlement + record in one step)

**Doctor does all of the following in one action:**
1. Enter the patient's wallet address and their encryption public key
2. Fill in Diagnosis, Prescription, and Notes
3. Click **Complete + Settle + Add Medical Record**

This single action does three things at once:
- Marks the appointment as `Completed`
- Transfers coins from the patient's balance to the doctor
- Encrypts the medical record and writes it to the blockchain

---

## Phase 5 – View Records

Either the patient or an authorized doctor can decrypt and view records:

1. Go to the **Clinical Explorer** section
2. Enter the patient's wallet address
3. Click **Decrypt profile**, **Decrypt records**, or **Decrypt allergies**
4. MetaMask will pop up asking you to confirm decryption
5. The plaintext data appears on screen

---

## Full Flow at a Glance

```
Doctor registers
                 ↘
                  Patient authorizes doctor
                  Patient receives coins
                 ↗
Patient registers
        ↓
Patient creates appointment  →  Doctor approves
        ↓
Doctor completes appointment
  └─ Settlement (coins transferred)
  └─ Medical record encrypted and stored on-chain
        ↓
Both parties can decrypt and view records via MetaMask
```

---

# 🖥️ How to run it

## Prerequisites

- **Node.js** – Download from [nodejs.org](https://nodejs.org) (LTS version recommended)
- **MetaMask** – Install as a browser extension in Chrome or Firefox
- **Truffle** – Install globally after Node.js is ready:
  ```bash
  npm install -g truffle
  ```

---

## Step 1 – Download the project

Download this project as a zip and extract it, or clone it:

```bash
git clone <This-webpage>
cd MedicalRecordSystem
```

---

## Step 2 – Install dependencies

```bash
npm install
```

---

## Step 3 – Start the frontend

```bash
npm run dev
```

Then open your browser and go to: `http://localhost:5000`

---

## Step 4 – Deploy the smart contracts

Choose one of the two options below:

### Option A: Ganache (local blockchain, fully offline, recommended for beginners)

1. Download and install [Ganache](https://trufflesuite.com/ganache/)
2. Launch Ganache – it runs on `http://127.0.0.1:7545` by default
3. In MetaMask, add a custom network:
   - Network Name: `Ganache`
   - RPC URL: `http://127.0.0.1:7545`
   - Chain ID: `5777`
4. Import one of the Ganache accounts into MetaMask using its private key
5. Deploy the contracts:
   ```bash
   npx truffle migrate
   ```
6. The terminal will print the two contract addresses, for example:
   ```
   PatientRegistry deployed at: 0xABC123...
   DoctorRegistry deployed at:  0xDEF456...
   ```

### Option B: Sepolia testnet (public test network, no Ganache needed)

1. In MetaMask, switch to the **Sepolia** network
2. Get free test ETH from [sepoliafaucet.com](https://sepoliafaucet.com)
3. Configure `truffle-config.js` with your Sepolia RPC endpoint and wallet private key
4. Deploy the contracts:
   ```bash
   npx truffle migrate --network sepolia
   ```
5. Copy the two contract addresses printed in the terminal

---

## Step 5 – Connect and use the app

1. Open `http://localhost:5000` in your browser
2. Paste the **PatientRegistry** contract address into the first field on the left
3. Paste the **DoctorRegistry** contract address into the second field
4. Click **Connect MetaMask** and approve the connection
5. Choose your role – **Patient** or **Doctor** – and start using the app

---

## Windows 11 Notes

All steps above work on Windows 11 with no changes. Use Command Prompt or PowerShell.

## Linux Notes

Install Node.js using your package manager or nvm:

```bash
# Ubuntu / Debian
sudo apt install nodejs npm

# Or use nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install --lts
```

Then follow the same steps from Step 2 onwards.
