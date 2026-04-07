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

# 📦 Installation

```bash
git clone <your-repo>
cd <project>
