const PatientRegistryABI = await fetch("./PatientRegistryABI.json").then((r) => r.json());
const DoctorRegistryABI = await fetch("./DoctorRegistryABI.json").then((r) => r.json());

const $ = (id) => document.getElementById(id);
const ContractAddress = "0x0000000000";

function getRadioGroupValue(containerId, groupName) {
  let root;
  if (containerId){
    root = document.getElementById(containerId);
  } else {
    root = document;
  }
  if (!root) return "";
  const el = root.querySelector(`input[name="${groupName}"]:checked`);
  return (el && el.value) ? String(el.value).trim() : "";
}

function getPatientGender() {
  return getRadioGroupValue("patientPanel", "p_gender");
}

function getDoctorGender() {
  return getRadioGroupValue("doctorPanel", "d_gender");
}

let provider;
let signer;
let contract;
let doctorContract;
let currentAccount;

async function isDoctorAuthorizedOnChain(doctorAddress, patientAddress) {
  if (!contract) throw new Error("PatientRegistry not loaded. Paste its address in either Wallet field.");
  return Boolean(await contract.patientDoctorAuthorized(patientAddress, doctorAddress));
}

function setStatus(msg) {
  $("status").innerText = msg;
}

function showError(err) {
  console.error(err);
  let msg = err?.shortMessage || err?.message || String(err);
  if (/BAD_DATA|could not decode result data/i.test(msg) && /0x/i.test(msg)) {
    msg =
      "Contract call returned empty data. Usually: wrong contract address, wrong network in MetaMask, or PatientRegistry not deployed at this address. Deploy with truffle migrate and paste the address for the same chain.";
  }
  const stackFirstLine = typeof err?.stack === "string" ? err.stack.split("\n")[0] : "";
  setStatus(stackFirstLine ? `Error: ${msg} (${stackFirstLine})` : `Error: ${msg}`);
}

// Smart contract to Web UI
function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Web UI to smart contract
function base64ToBytes(b64) {
  if (typeof b64 !== "string") {
    throw new Error(`base64ToBytes expects string, got ${typeof b64}`);
  }
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

const ENC_VERSION = "x25519-xsalsa20-poly1305";

// String to hash
async function sha256StringToHex32(str) {
  const bytes = new TextEncoder().encode(str);
  return sha256BytesToHex32(bytes);
}

// Generate hash value
async function sha256BytesToHex32(bytesU8) {
  const digest = await crypto.subtle.digest("SHA-256", bytesU8);
  const u8 = new Uint8Array(digest);
  return (
    "0x" +
    Array.from(u8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

// Handling MetaMask error
function MetaMaskAuthError(err, rpcMethod) {
  const code = err?.code;
  const msg = err?.message || String(err);
  const hint = rpcMethod ? ` (${rpcMethod})` : "";
  if (code === 4001 || /user rejected|rejected the request/i.test(msg)) {
    return `MetaMask request was cancelled${hint}. Approve the prompt to continue.`;
  }
  if (code === 4100 || /not been authorized|Unauthorized/i.test(msg)) {
    return (
      `MetaMask account or method not authorized${hint}. Click Connect on this page, unlock MetaMask, and approve access. `
    );
  }
  return null;
}

async function getEncryptionPublicKey(address) {
  if (!window.ethereum) throw new Error("MetaMask not found (window.ethereum missing).");
  let res;
  try {
    res = await window.ethereum.request({
      method: "eth_getEncryptionPublicKey",
      params: [address],
    });
  } catch (e) {
    const explained = MetaMaskAuthError(e, "eth_getEncryptionPublicKey");
    throw new Error(explained || e?.message || String(e));
  }
  if (typeof res === "string") return res;
  if (res && typeof res.publicKey === "string") return res.publicKey;
  throw new Error(`Unexpected eth_getEncryptionPublicKey result: ${String(res)}`);
}


function parsePastedEncryptionPublicKeyBase64(pasted) {
  const _string = String(pasted ?? "").trim();
  if (!_string) return null;
  try {
    const b = base64ToBytes(_string);
    if (b.length !== 32) {
      throw new Error(`Encryption public key must be base64 decoding to 32 bytes (${b.length}).`);
    }
  } catch (e) {
    if (e.message && e.message.includes("32 bytes")) throw e;
    throw new Error("Encryption public key must be valid base64 (MetaMask x25519 public key).");
  }
  return _string;
}

async function resolveRecipientEncryptionPublicKey(recipientEthAddress, pastedPatientPubKeyOptional) {
  if (!currentAccount) throw new Error("Connect wallet first.");
  const rec = ethers.getAddress(recipientEthAddress);
  const cur = ethers.getAddress(currentAccount);
  if (rec.toLowerCase() === cur.toLowerCase()) {
    return getEncryptionPublicKey(cur);
  }
  const fromPaste = parsePastedEncryptionPublicKeyBase64(pastedPatientPubKeyOptional);
  if (fromPaste) return fromPaste;
  throw new Error(
    "Cannot fetch another person's encryption public key. Please paste the patient's encryption public key (base64, usually ending with ==) "
  );
}

// Load TweetNaCL, prepare for encryption
function encryptForRecipient(recipientEncryptionPublicKey, plaintext) {
  // Browser-native encryption implementation (x25519-xsalsa20-poly1305).
  // This avoids relying on eth-sig-util's CDN/UMD/global wiring.
  // Checking for the library
  const naclLib = window.nacl || globalThis.nacl;
  if (!naclLib?.box?.keyPair || typeof naclLib.box.nonceLength !== "number") {
    throw new Error("tweetnacl not loaded (nacl.box.encrypt missing).");
  }

  if (typeof plaintext !== "string") plaintext = String(plaintext);

  // MetaMask returns `publicKey` as base64 (but we defensively handle objects).
  if (recipientEncryptionPublicKey && typeof recipientEncryptionPublicKey !== "string") {
    if (typeof recipientEncryptionPublicKey.publicKey === "string") {
      recipientEncryptionPublicKey = recipientEncryptionPublicKey.publicKey;
    } else {
      throw new Error(
        `encryptForRecipient: recipientEncryptionPublicKey must be base64 string, got ${typeof recipientEncryptionPublicKey}`
      );
    }
  }

  const recipientPubKeyBytes = base64ToBytes(recipientEncryptionPublicKey);
  if (recipientPubKeyBytes.length !== 32) {
    throw new Error(`Invalid recipient public key byte length: ${recipientPubKeyBytes.length} (expected 32).`);
  }
  const messageBytes = new TextEncoder().encode(plaintext);

  // Ephemeral key pair for x25519.
  const ephemeralKeyPair = naclLib.box.keyPair();
  const nonce = naclLib.randomBytes(naclLib.box.nonceLength);
  if (nonce.length !== naclLib.box.nonceLength) {
    throw new Error(`Invalid nonce length: ${nonce.length} (expected ${naclLib.box.nonceLength}).`);
  }
  if (ephemeralKeyPair.secretKey.length !== 32 || ephemeralKeyPair.publicKey.length !== 32) {
    throw new Error(`Invalid ephemeral key sizes (public=${ephemeralKeyPair.publicKey.length}, secret=${ephemeralKeyPair.secretKey.length}).`);
  }

  // Encrypt message (tweetnacl box returns Uint8Array).
  const encryptedMessage = naclLib.box(
    messageBytes,
    nonce,
    recipientPubKeyBytes,
    ephemeralKeyPair.secretKey
  );

  return {
    version: ENC_VERSION,
    nonce: bytesToBase64(nonce),
    ephemPublicKey: bytesToBase64(ephemeralKeyPair.publicKey),
    ciphertext: bytesToBase64(encryptedMessage),
  };
}

async function decryptWithMetaMask(encryptedDataObj) {
  // MetaMask expects an eth-sig-util style "EthEncryptedData" object:
  // { version: string; nonce: string; ephemPublicKey: string; ciphertext: string }
  // Older/legacy on-chain data might have serialized byte arrays into plain objects,
  // which can cause internal Buffer.from(...) type errors.
  if (typeof encryptedDataObj === "string") {
    try {
      encryptedDataObj = JSON.parse(encryptedDataObj);
    } catch {
      // Fall through to the validation below.
    }
  }

  if (!encryptedDataObj || typeof encryptedDataObj !== "object") {
    throw new Error(`Invalid encryptedDataObj: expected object, got ${typeof encryptedDataObj}`);
  }

  function bytesToUint8Array(value, fieldName) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (Array.isArray(value)) return new Uint8Array(value);

    // Handle common JSON-serialized Buffer shapes (e.g. { type: "Buffer", data: [...] }).
    if (value && typeof value === "object" && value.data != null) {
      const d = value.data;
      if (d instanceof Uint8Array) return d;
      if (d instanceof ArrayBuffer) return new Uint8Array(d);
      if (Array.isArray(d)) return new Uint8Array(d);
    }

    // Handle JSON-serialized typed arrays (e.g. {"0":12,"1":34,...}).
    if (value && typeof value === "object") {
      const keys = Object.keys(value)
        .filter((k) => String(Number(k)) === k)
        .sort((a, b) => Number(a) - Number(b));
      if (keys.length > 0) {
        const arr = keys.map((k) => value[k]);
        return new Uint8Array(arr);
      }
    }

    throw new Error(`Unable to normalize ${fieldName} into byte data. Got ${typeof value}`);
  }

  function ensureBase64String(value, fieldName) {
    if (typeof value === "string") return value;
    if (value instanceof String) return value.toString();

    // Some wallets/serializers store payloads as objects like { base64: "..." } or { data: "..." }.
    if (value && typeof value === "object") {
      if (typeof value.base64 === "string") return value.base64;
      if (typeof value.data === "string") return value.data;
    }

    const bytes = bytesToUint8Array(value, fieldName);
    return bytesToBase64(bytes);
  }

  const { version, nonce, ephemPublicKey, ciphertext } = encryptedDataObj;

  const normalized = {
    version:
      typeof version === "string" ? version : version instanceof String ? version.toString() : String(version),
    nonce: ensureBase64String(nonce, "nonce"),
    ephemPublicKey: ensureBase64String(ephemPublicKey, "ephemPublicKey"),
    ciphertext: ensureBase64String(ciphertext, "ciphertext"),
  };

  const typeSummary = {
    version: typeof normalized.version,
    nonce: typeof normalized.nonce,
    ephemPublicKey: typeof normalized.ephemPublicKey,
    ciphertext: typeof normalized.ciphertext,
  };

  if (
    typeof normalized.version !== "string" ||
    typeof normalized.nonce !== "string" ||
    typeof normalized.ephemPublicKey !== "string" ||
    typeof normalized.ciphertext !== "string"
  ) {
    throw new Error(
      `Invalid encrypted payload for eth_decrypt. Expected {version, nonce, ephemPublicKey, ciphertext} as base64 strings. Got types: ${JSON.stringify(
        typeSummary
      )}`
    );
  }

  // MetaMask's `eth_decrypt` expects the *encrypted payload* to be passed as a hex string.
  // In practice, MetaMask hex-encodes `JSON.stringify(EthEncryptedData)` bytes (see common examples).
  function bytesToHex(bytesU8) {
    // Ensure we don't accidentally pass something non-Uint8Array-like.
    const u8 = bytesU8 instanceof Uint8Array ? bytesU8 : new Uint8Array(bytesU8);
    return (
      "0x" +
      Array.from(u8)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
    );
  }

  const encryptedJsonBytes = new TextEncoder().encode(JSON.stringify(normalized));
  const encryptedHexString = bytesToHex(encryptedJsonBytes);

  // MetaMask will decrypt inside the wallet for the current connected account.
  try {
    return await window.ethereum.request({
      method: "eth_decrypt",
      params: [encryptedHexString, currentAccount],
    });
  } catch (e) {
    const explained = MetaMaskAuthError(e, "eth_decrypt");
    const errMsg = explained || e?.shortMessage || e?.message || String(e);
    const normLens = {
      nonce: normalized.nonce?.length,
      ephemPublicKey: normalized.ephemPublicKey?.length,
      ciphertext: normalized.ciphertext?.length,
    };
    throw new Error(
      `MetaMask eth_decrypt failed: ${errMsg}. Payload types (input): ${JSON.stringify(
        typeSummary
      )}; normalized lengths: ${JSON.stringify(normLens)}`
    );
  }
}

function showPanelByRole(role) {
  const isDoctor = role === "doctor";
  const isPatient = role === "patient";
  const isUnknown = role === "unknown";
  const isPreConnect = !currentAccount;

  const hasPatientRegistry = Boolean(contract);
  const hasDoctorRegistry = Boolean(doctorContract);

  /** Wallets not registered as patients are usually providers; keep doctor tools visible for them too. */
  const doctorWorkflow = isDoctor || isUnknown;

  const roleSelectPanel = $("roleSelectPanel");
  if (roleSelectPanel) roleSelectPanel.style.display = isPreConnect ? "none" : (isUnknown ? "block" : "none");

  const patientPanelEl = $("patientPanel");
  if (patientPanelEl) patientPanelEl.style.display = !isPreConnect && isPatient ? "block" : "none";
  const patientView = $("PatientViewProfile");
  if (patientView) {
    patientView.style.display =
      hasPatientRegistry && (isPatient || doctorWorkflow) ? "block" : "none"; //Ensure doctor can view the patient's profile
  }

  const doctorPanelEl = $("doctorPanel");
  if (doctorPanelEl) doctorPanelEl.style.display = !isPreConnect && isDoctor ? "block" : "none";
  const doctorView = $("DoctorViewProfile");
  if (doctorView) doctorView.style.display = isDoctor ? "block" : "none";

  const medPanel = $("medicalRecordPanel");
  if (medPanel) medPanel.style.display = hasPatientRegistry && doctorWorkflow ? "block" : "none";

  const medDecrypt = $("medicalRecordDecryptPanel");
  if (medDecrypt) medDecrypt.style.display = hasPatientRegistry && (isPatient || doctorWorkflow) ? "block" : "none";

  const allergyDecrypt = $("allergyDecryptPanel");
  if (allergyDecrypt) allergyDecrypt.style.display = hasPatientRegistry && (isPatient || doctorWorkflow) ? "block" : "none";

  const authPatientsPanel = $("doctorAuthorizedPatientsPanel");
  if (authPatientsPanel) authPatientsPanel.style.display = hasPatientRegistry && doctorWorkflow ? "block" : "none";

  const updateBtn = $("updateProfileBtn");
  if (updateBtn) updateBtn.style.display = isPatient ? "" : "none";

  const choosePatientBtn = $("choosePatientBtn");
  const chooseDoctorBtn = $("chooseDoctorBtn");
  const hint = $("roleSelectHint");

  // Select their preferred role
  if (isPreConnect) {
    if (choosePatientBtn) {
      choosePatientBtn.style.display = "";
      choosePatientBtn.disabled = true;
    }
    if (chooseDoctorBtn) {
      chooseDoctorBtn.style.display = "";
      chooseDoctorBtn.disabled = true;
    }
    if (hint) hint.innerText = "Connect MetaMask first, then pick the role to continue.";
  } else if (!hasPatientRegistry && !hasDoctorRegistry) {
    if (choosePatientBtn) {
      choosePatientBtn.style.display = "";
      choosePatientBtn.disabled = true;
    }
    if (chooseDoctorBtn) {
      chooseDoctorBtn.style.display = "";
      chooseDoctorBtn.disabled = true;
    }
    if (hint) hint.innerText = "Paste at least one registry address in the Wallet section, then connect again.";
  } else {
    const showDoctorRole = hasPatientRegistry || hasDoctorRegistry;
    if (choosePatientBtn) {
      choosePatientBtn.style.display = hasPatientRegistry ? "" : "none";
      choosePatientBtn.disabled = false;
    }
    if (chooseDoctorBtn) {
      chooseDoctorBtn.style.display = showDoctorRole ? "" : "none";
      chooseDoctorBtn.disabled = false;
    }
    if (hint) {
      if (hasPatientRegistry && hasDoctorRegistry) {
        hint.innerText = "Choose Patient or Doctor. Doctor tools use PatientRegistry for records; DoctorRegistry is for your on-chain doctor profile.";
      } else if (hasPatientRegistry && !hasDoctorRegistry) {
        hint.innerText =
          "PatientRegistry only: you can act as patient or as doctor (add/view records).";
      } else {
        hint.innerText =
          "DoctorRegistry only: doctor profile tools are available. Add PatientRegistry for patient data, records, allergies, and authorizations.";
      }
    }
  }

  if (isPatient && currentAccount) {
    const readPatient = $("readPatientAddress");
    if (readPatient && !(readPatient.value || "").trim()) readPatient.value = currentAccount;
    const readAllergy = $("allergyReadPatientAddress");
    if (readAllergy && !(readAllergy.value || "").trim()) readAllergy.value = currentAccount;
  }

  // Shared session
  const clinicalRoot = $("clinicalSharedSection");
  if (clinicalRoot && patientPanelEl && doctorPanelEl) {
    const showClinical = isPreConnect
      ? true
      : hasPatientRegistry && (isPatient || isDoctor || (isUnknown && doctorWorkflow));
    if (!showClinical) {
      clinicalRoot.style.display = "none";
    } else {
      clinicalRoot.style.display = "block";
      if (isPreConnect || isUnknown) {
        const scriptTag = document.querySelector("script[src*='app.js']");
        const anchor = scriptTag?.parentNode || document.body;
        anchor.insertBefore(clinicalRoot, scriptTag || null);
      } else if (isPatient) {
        patientPanelEl.appendChild(clinicalRoot);
      } else if (isDoctor) {
        doctorPanelEl.appendChild(clinicalRoot);
      }
    }
  }

  const appointmentPanel = $("appointmentPanel");
  if (appointmentPanel) {
    appointmentPanel.style.display = !isPreConnect && hasPatientRegistry ? "block" : "none";
  }
}

// Connect to MetaMask
async function connectWallet() {
  if (!window.ethereum) throw new Error("MetaMask not found.");
  provider = new ethers.BrowserProvider(window.ethereum);
  try {
    await provider.send("eth_requestAccounts", []);
  } catch (e) {
    const explain = MetaMaskAuthError(e, "eth_requestAccounts");
    throw new Error(explain || e?.message || String(e));
  }
  signer = await provider.getSigner();
  currentAccount = await signer.getAddress();

  $("accountLabel").innerText = currentAccount;
  await refreshNetworkLabel();
  setStatus("Wallet connected.");
}

// List the chain names
const CHAIN_NAMES = new Map([
  [1n, "Ethereum Mainnet"],
  [11155111n, "Sepolia"],
  [5n, "Goerli"],
  [5777n, "Ganache (default)"],
  [1337n, "Hardhat / local"],
  [31337n, "Anvil / Hardhat"],
]);

async function refreshNetworkLabel() {
  const netlab = $("networkLabel");
  if (!netlab) return;
  if (!provider) {
    netlab.innerText = "Network: —";
    return;
  }
  try {
    const net = await provider.getNetwork();
    const cid = net.chainId;
    const name = CHAIN_NAMES.get(cid) || "custom";
    netlab.innerText = `Network: chainId ${cid} (${name}) — must match Truffle/Ganache`;
  } catch {
    netlab.innerText = "Network: (could not read)";
  }
}

/** Ensures `address` has contract bytecode (avoids ethers BAD_DATA / 0x when calling views). */
async function ensureContractBytecode(address, label = "contract") {
  if (!provider) throw new Error("Connect wallet first.");
  const code = await provider.getCode(address);
  if (!code || code === "0x") {
    const net = await provider.getNetwork();
    const cid = net.chainId;
    let hint =
      " The address from `truffle migrate` only exists on the blockchain where you deployed (same chainId).";
    if (cid === 1n) {
      hint =
        " MetaMask is on Ethereum Mainnet (chainId 1). Ganache’s default chainId is usually 5777. In MetaMask, switch to your Localhost 8545 / Ganache network, then try again.";
    } else if (cid === 11155111n || cid === 5n) {
      hint +=
        " You are on a public testnet; deploy there or switch MetaMask to your local Ganache network.";
    }
    throw new Error(
      `No contract at ${address} on chainId ${cid}. Deploy ${label} on this network and paste its address.${hint}`
    );
  }
}


 
// Identify PatientRegistry or DoctorRegistry
async function probeRegistryKind(address) {
  await ensureContractBytecode(address, "registry contract");
  const patReader = new ethers.Contract(address, PatientRegistryABI, provider);
  try {
    await patReader.patients(ethers.ZeroAddress);
    return "patient";
  } catch {

  }
  const docReader = new ethers.Contract(address, DoctorRegistryABI, provider);
  try {
    await docReader.doctors(ethers.ZeroAddress);
    return "doctor";
  } catch {
    throw new Error(
      `${address} is neither PatientRegistry nor DoctorRegistry on this network. Check MetaMask uses the same chain as truffle migrate.`
    );
  }
}

function requirePatientRegistryContract() {
  if (!contract) {
    throw new Error(
      "This action needs PatientRegistry. Please paste its address."
    );
  }
}

async function makeContract() {
  const rawA = $("contractAddress")?.value || "" || ContractAddress.trim();
  const rawB = $("doctorRegistryAddress")?.value || "" || ContractAddress.trim();

  const seen = new Set();
  const candidates = [];
  for (const r of [rawA, rawB]) {
    if (!r || r === "0x0000000000" || !ethers.isAddress(r)) continue;
    const key = r.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push(r);
  }

  contract = null;
  doctorContract = null;

  if (candidates.length === 0) {
    return;
  }

  let patientAddr = null;
  let doctorAddr = null;

  for (const addr of candidates) {
    const kind = await probeRegistryKind(addr);
    if (kind === "patient") {
      if (patientAddr && patientAddr.toLowerCase() !== addr.toLowerCase()) {
        throw new Error("Two different PatientRegistry addresses found. Use only one PatientRegistry deployment.");
      }
      patientAddr = addr;
    } else {
      if (doctorAddr && doctorAddr.toLowerCase() !== addr.toLowerCase()) {
        throw new Error("Two different DoctorRegistry addresses found. Use only one DoctorRegistry deployment.");
      }
      doctorAddr = addr;
    }
  }

  if (patientAddr) {
    contract = new ethers.Contract(patientAddr, PatientRegistryABI, signer);
  }
  if (doctorAddr) {
    doctorContract = new ethers.Contract(doctorAddr, DoctorRegistryABI, signer);
  }
}

async function makeDoctorContract(required = false) {
  await makeContract();
  if (required && !doctorContract) {
    const typed =
      Boolean($("contractAddress")?.value?.trim()) || Boolean($("doctorRegistryAddress")?.value?.trim());
    throw new Error(
      typed
        ? "DoctorRegistry not found. Please paste a valid DoctorRegistry address."
        : "Please paste the DoctorRegistry contract address."
    );
  }
}

async function detectRoleFromContract() {
  if (!contract && !doctorContract) {
    showPanelByRole("unknown");
    setStatus(
      "Wallet connected. Paste PatientRegistry and/or DoctorRegistry in either Wallet field, then connect again."
    );
    return;
  }

  if (!contract && doctorContract) {
    showPanelByRole("doctor");
    setStatus(
      "DoctorRegistry only: you can register or load your doctor profile without being a patient. Add PatientRegistry to use records, allergies, and authorizations."
    );
    return;
  }

  const acc = currentAccount;
  const isPatient = await contract.patients(acc);
  const role = isPatient ? "patient" : "unknown";
  showPanelByRole(role);
  if (role === "unknown") {
    setStatus(
      "Wallet is not registered as a patient on this registry."
    );
  } else {
    setStatus("Role detected: registered patient.");
  }
}

async function registerPatient() {
  try {
    await makeContract();
    requirePatientRegistryContract();

    const profilePlain = {
      name: $("p_name").value.trim(),
      idCard: $("p_idCard").value.trim(),
      birthDay: $("p_birthDay").value.trim(),
      gender: getPatientGender(),
      homeAddress: $("p_homeAddress").value.trim(),
      phoneNumber: $("p_phoneNumber").value.trim(),
      age: Number($("p_age").value),
      weight: Number($("p_weight").value),
      height: Number($("p_height").value),
    };

    if (!profilePlain.name) throw new Error("Name is required.");
    if (!profilePlain.idCard) throw new Error("ID Card is required.");
    if (!profilePlain.birthDay) throw new Error("Birth day is required.");
    if (!profilePlain.gender) throw new Error("Gender is required (choose Male or Female).");
    if (!profilePlain.homeAddress) throw new Error("Home address is required.");
    if (!profilePlain.phoneNumber) throw new Error("Phone number is required.");
    if (!profilePlain.age) throw new Error("Age is required.");
    if (!profilePlain.weight) throw new Error("Weight is required.");
    if (!profilePlain.height) throw new Error("Height is required.");

    const encryptedStr = await buildEncryptedProfileForChain(profilePlain);
    const profileHash = await sha256StringToHex32(encryptedStr);

    setStatus("Submitting registerPatient (MetaMask encrypted profile)...");
    const tx = await contract.registerPatient(encryptedStr, profileHash);
    await tx.wait();
    setStatus("Register patient confirmed.");
  } catch (e) {
    showError(e);
  }
}

async function updateProfile() {
  try {
    await makeContract();
    requirePatientRegistryContract();

    const profilePlain = {
      name: $("p_name").value.trim(),
      idCard: $("p_idCard").value.trim(),
      birthDay: $("p_birthDay").value.trim(),
      gender: getPatientGender(),
      homeAddress: $("p_homeAddress").value.trim(),
      phoneNumber: $("p_phoneNumber").value.trim(),
      age: Number($("p_age").value),
      weight: Number($("p_weight").value),
      height: Number($("p_height").value),
    };

    if (!profilePlain.name) throw new Error("Name is required.");
    if (!profilePlain.idCard) throw new Error("ID Card is required.");
    if (!profilePlain.birthDay) throw new Error("Birth day is required.");
    if (!profilePlain.gender) throw new Error("Gender is required (choose Male or Female).");
    if (!profilePlain.homeAddress) throw new Error("Home address is required.");
    if (!profilePlain.phoneNumber) throw new Error("Phone number is required.");
    if (!profilePlain.age) throw new Error("Age is required.");
    if (!profilePlain.weight) throw new Error("Weight is required.");
    if (!profilePlain.height) throw new Error("Height is required.");

    const encryptedStr = await buildEncryptedProfileForChain(profilePlain);
    const profileHash = await sha256StringToHex32(encryptedStr);

    setStatus("Submitting updateProfile (MetaMask encrypted profile)...");
    const tx = await contract.updateProfile(encryptedStr, profileHash);
    await tx.wait();
    setStatus("updateProfile tx confirmed.");
  } catch (e) {
    showError(e);
  }
}

async function buildEncryptedProfileForChain(profilePlain) {
  const patientPubKey = await getEncryptionPublicKey(currentAccount);
  const encryptedForPatient = encryptForRecipient(patientPubKey, JSON.stringify(profilePlain));
  const wrapper = { patient: encryptedForPatient, doctors: {} };

  const doctorAddressRaw = ($("profileDoctorAddressForShare")?.value || "").trim();
  const doctorPubKeyRaw = ($("profileDoctorEncryptionPubKeyForShare")?.value || "").trim();

  if (doctorAddressRaw || doctorPubKeyRaw) {
    if (!ethers.isAddress(doctorAddressRaw)) {
      throw new Error("Doctor address for profile sharing is invalid.");
    }
    const doctorPubKey = parsePastedEncryptionPublicKeyBase64(doctorPubKeyRaw);
    if (!doctorPubKey) {
      throw new Error("Doctor encryption public key is required when sharing profile with a doctor.");
    }
    const normalizedDoctor = ethers.getAddress(doctorAddressRaw).toLowerCase();
    wrapper.doctors[normalizedDoctor] = encryptForRecipient(doctorPubKey, JSON.stringify(profilePlain));
  }

  return JSON.stringify(wrapper);
}

async function showMyEncryptionPublicKeyForDoctor() {
  try {
    if (!window.ethereum) throw new Error("MetaMask not found.");
    if (!currentAccount) throw new Error("Connect wallet first.");
    setStatus("Requesting encryption public key from MetaMask…");
    const pk = await getEncryptionPublicKey(currentAccount);
    const doctorKeyField = $("d_publicKey");
    if (doctorKeyField) doctorKeyField.value = pk;
    const out = $("encryptionPubKeyOutput");
    if (out) out.textContent = pk;
    setStatus("Encryption public key loaded into Doctor profile field.");
  } catch (e) {
    showError(e);
  }
}

async function getMyProfileDecrypted() {
  try {
    await makeContract();
    requirePatientRegistryContract();

    const raw = $("profileReadPatientAddress")?.value || "";
    const patientAddress = raw && ethers.isAddress(raw) ? raw : currentAccount;
    if (!ethers.isAddress(patientAddress)) throw new Error("Invalid or missing patient address.");
    if (
      currentAccount.toLowerCase() !== patientAddress.toLowerCase() &&
      !(await isDoctorAuthorizedOnChain(currentAccount, patientAddress))
    ) {
      throw new Error("Access denied: this patient has not authorized your doctor wallet on-chain.");
    }

    const [encryptedStr, onChainProfileHash] = await contract.getMyProfile(patientAddress);
    if (!encryptedStr) throw new Error("No encrypted profile found.");
    const recomputed = await sha256StringToHex32(encryptedStr);
    if (recomputed.toLowerCase() !== String(onChainProfileHash).toLowerCase()) {
      throw new Error("Profile integrity check failed (profileHash mismatch).");
    }

    const encryptedObj = JSON.parse(encryptedStr);
    const patientLc = patientAddress.toLowerCase();
    const meLc = currentAccount.toLowerCase();
    let encryptedForMe;

    // Backward compatible:
    // - legacy profile payload: single encrypted object
    // - new profile payload: { patient, doctors: { "<doctorAddressLower>": <encObj> } }
    if (encryptedObj && typeof encryptedObj === "object" && encryptedObj.patient) {
      if (meLc === patientLc) {
        encryptedForMe = encryptedObj.patient;
      } else {
        const doctors = encryptedObj.doctors || {};
        encryptedForMe = doctors[meLc];
        if (!encryptedForMe) {
          throw new Error(
            "Profile is not encrypted for this doctor wallet yet. Ask the patient to update profile and paste your encryption public key."
          );
        }
      }
    } else {
      encryptedForMe = encryptedObj;
    }

    const plaintext = await decryptWithMetaMask(encryptedForMe);
    const json = JSON.parse(plaintext);

    const outP = $("profileOutput_P");
    if (outP) outP.innerText = JSON.stringify(json, null, 2);
    setStatus("Profile decrypted using MetaMask.");
  } catch (e) {
    showError(e);
  }
}

async function encryptMedicalRecordForChain(patientAddress, recordObj, patientPubKeyPastedOptional) {
  const doctorPubKey = await getEncryptionPublicKey(currentAccount);
  const patientPubKey = await resolveRecipientEncryptionPublicKey(patientAddress, patientPubKeyPastedOptional);
  const encryptedForDoctor = encryptForRecipient(doctorPubKey, JSON.stringify(recordObj));
  const encryptedForPatient = encryptForRecipient(patientPubKey, JSON.stringify(recordObj));
  const wrapper = { doctor: encryptedForDoctor, patient: encryptedForPatient };
  const encryptedDataString = JSON.stringify(wrapper);
  const contentHash = await sha256StringToHex32(encryptedDataString);
  return { encryptedDataString, contentHash };
}

async function encryptAllergyPayloadForChain(patientAddress, allergyObj, patientPubKeyPastedOptional) {
  const patientPubKey = await resolveRecipientEncryptionPublicKey(patientAddress, patientPubKeyPastedOptional);
  const doctorPubKey = await getEncryptionPublicKey(currentAccount);
  const encryptedForPatient = encryptForRecipient(patientPubKey, JSON.stringify(allergyObj));
  const encryptedForDoctor = encryptForRecipient(doctorPubKey, JSON.stringify(allergyObj));
  const wrapper = { patient: encryptedForPatient, doctor: encryptedForDoctor };
  const encryptedStr = JSON.stringify(wrapper);
  const allergyHash = await sha256StringToHex32(encryptedStr);
  return { encryptedStr, allergyHash };
}

async function addMedicalRecord() {
  try {
    await makeDoctorContract(true);
    requirePatientRegistryContract();
    const patientAddress = $("recordPatientAddress").value || "";
    if (!ethers.isAddress(patientAddress)) throw new Error("Invalid patient address.");
    if (!(await isDoctorAuthorizedOnChain(currentAccount, patientAddress))) {
      throw new Error("Access denied: this patient has not authorized your doctor wallet on-chain.");
    }
    const diagnosis = ($("recordD")?.value || "").trim();
    const prescription = ($("recordP")?.value || "").trim();
    const notes = ($("recordN")?.value || "").trim();
    if (!diagnosis && !prescription && !notes) {
      throw new Error("Enter at least one of diagnosis, prescription, or notes.");
    }
    const recordObj = { diagnosis, prescription, notes };
    const pastedPk = ($("recordPatientEncryptionPubKey")?.value || "").trim();
    const { encryptedDataString, contentHash } = await encryptMedicalRecordForChain(
      patientAddress,
      recordObj,
      pastedPk
    );
    const registryAddr = await contract.getAddress();
    setStatus("Submitting addMedicalRecordByDoctor on DoctorRegistry...");
    const tx = await doctorContract.addMedicalRecordByDoctor(registryAddr, patientAddress, contentHash, encryptedDataString);
    await tx.wait();
    setStatus("addMedicalRecordByDoctor tx confirmed.");
  } catch (e) {
    showError(e);
  }
}

async function getMedicalRecordsDecryptAndVerify() {
  try {
    await makeContract();
    requirePatientRegistryContract();
    const patientAddress = $("readPatientAddress").value || "";
    if (!ethers.isAddress(patientAddress)) throw new Error("Invalid patient address.");
    if (
      currentAccount.toLowerCase() !== patientAddress.toLowerCase() &&
      !(await isDoctorAuthorizedOnChain(currentAccount, patientAddress))
    ) {
      throw new Error("Access denied: this patient has not authorized your doctor wallet on-chain.");
    }

    setStatus("Reading encrypted records from chain...");
    const records = await contract.getMedicalRecord(patientAddress);

    const out = [];
    for (const r of records) {
      const encryptedDataString = r.encryptedData;
      const recomputedHash = await sha256StringToHex32(encryptedDataString);
      const verified =
        recomputedHash.toLowerCase() === String(r.contentHash).toLowerCase();

      if (!verified) {
        out.push({
          recordId: r.recordId?.toString ? r.recordId.toString() : r.recordId,
          verified: false,
          doctorName: r.doctorName,
          date: r.date?.toString ? Number(r.date.toString()) : r.date,
          error: "Integrity check failed (contentHash mismatch).",
        });
        continue;
      }

      // encryptedDataString is a JSON wrapper: { doctor: <encObj>, patient: <encObj> }
      const wrapper = JSON.parse(encryptedDataString);
      const encForMe =
        currentAccount.toLowerCase() === String(r.doctorAddress).toLowerCase()
          ? wrapper.doctor
          : wrapper.patient;

      const plaintext = await decryptWithMetaMask(encForMe);
      const payload = JSON.parse(plaintext);

      out.push({
        recordId: r.recordId?.toString ? r.recordId.toString() : r.recordId,
        verified: true,
        doctorName: r.doctorName,
        date: r.date?.toString ? Number(r.date.toString()) : r.date,
        payload,
      });
    }

    $("recordsOutput").innerText = JSON.stringify(out, null, 2);
    setStatus("Records decrypted using MetaMask + verified against contentHash.");
  } catch (e) {
    showError(e);
  }
}

async function loadAuthorizedPatientsForDoctor() {
  try {
    await makeContract();
    requirePatientRegistryContract();
    if (!currentAccount) throw new Error("Connect wallet first.");

    setStatus("Scanning DoctorAuthorizationUpdated events…");
    const filter = contract.filters.DoctorAuthorizationUpdated(null, currentAccount);
    const head = await provider.getBlockNumber();
    const logs = await contract.queryFilter(filter, 0, head);

    logs.sort((a, b) => {
      const d = Number(a.blockNumber - b.blockNumber);
      if (d !== 0) return d;
      const ti = Number(a.transactionIndex - b.transactionIndex);
      if (ti !== 0) return ti;
      return Number(a.index - b.index);
    });

    const lastByPatient = new Map();
    for (const log of logs) {
      const patient = log.args?.patient ?? log.args?.[0];
      const authorized =
        typeof log.args?.authorized === "boolean" ? log.args.authorized : Boolean(log.args?.[2]);
      if (patient == null) continue;
      const addr = ethers.getAddress(String(patient));
      lastByPatient.set(addr.toLowerCase(), { patient: addr, authorized: Boolean(authorized) });
    }

    const authorizedNow = [];
    for (const { patient, authorized } of lastByPatient.values()) {
      if (!authorized) continue;
      const ok = await contract.patientDoctorAuthorized(patient, currentAccount);
      if (!ok) continue;
      const registered = await contract.patients(patient);
      authorizedNow.push({ patient, registered });
    }

    const container = $("authorizedPatientsList");
    if (container) {
      container.innerHTML = "";
      if (authorizedNow.length === 0) {
        container.innerHTML =
          '<p class="muted">No active authorizations found for this wallet (or no events in range). Patients must call setDoctorAuthorization for your address.</p>';
      } else {
        for (const { patient, registered } of authorizedNow) {
          const row = document.createElement("div");
          row.className = "row";
          const btn = document.createElement("button");
          btn.type = "button";
          const short = `${patient.slice(0, 8)}…${patient.slice(-6)}`;
          btn.textContent = registered
            ? `View records — ${short}`
            : `View records — ${short} (patient not registered on chain)`;
          btn.addEventListener("click", () => {
            const rec = $("readPatientAddress");
            if (rec) rec.value = patient;
            const al = $("allergyReadPatientAddress");
            if (al) al.value = patient;
            setStatus(`Patient address filled: ${patient}`);
          });
          row.appendChild(btn);
          container.appendChild(row);
        }
      }
    }

    setStatus(
      authorizedNow.length === 0
        ? "No authorized patients found from events."
        : `Found ${authorizedNow.length} patient(s).`
    );
  } catch (e) {
    showError(e);
  }
}

async function addAllergyViaDoctorRegistry() {
  try {
    await makeDoctorContract(true);
    requirePatientRegistryContract();
    const allergen = ($("allergyAllergenDr")?.value || "").trim();
    const severity = ($("allergySeverityDr")?.value || "").trim();
    const reaction = ($("allergyReactionDr")?.value || "").trim();
    const rawPatient = $("allergyPatientAddressDr")?.value || "";
    if (!ethers.isAddress(rawPatient)) throw new Error("Invalid patient address.");
    const patientAddress = rawPatient;
    if (!(await isDoctorAuthorizedOnChain(currentAccount, patientAddress))) {
      throw new Error("Access denied: this patient has not authorized your doctor wallet on-chain.");
    }
    if (!allergen || !severity || !reaction) throw new Error("Allergen, severity, reaction are required.");
    const allergyObj = { allergen, severity, reaction };
    const pastedPk = ($("allergyPatientEncryptionPubKeyDr")?.value || "").trim();
    const { encryptedStr, allergyHash } = await encryptAllergyPayloadForChain(
      patientAddress,
      allergyObj,
      pastedPk
    );
    const registryAddr = await contract.getAddress();
    setStatus("Submitting addAllergyByDoctor on DoctorRegistry...");
    const tx = await doctorContract.addAllergyByDoctor(registryAddr, patientAddress, encryptedStr, allergyHash);
    await tx.wait();
    setStatus("addAllergyByDoctor tx confirmed.");
  } catch (e) {
    showError(e);
  }
}

async function loadRegisteredDoctors() {
  try {
    await makeDoctorContract(true);
    setStatus("Scanning DoctorRegistered events…");
    const filter = doctorContract.filters.DoctorRegistered();
    const head = await provider.getBlockNumber();
    const logs = await doctorContract.queryFilter(filter, 0, head);

    const doctorsList = [];
    const seen = new Set();
    
    for (let i = logs.length - 1; i >= 0; i--) {
      const log = logs[i];
      const docAddr = log.args?.doctor ?? log.args?.[0];
      if (!docAddr) continue;
      const addr = ethers.getAddress(String(docAddr));
      if (seen.has(addr)) continue;
      seen.add(addr);

      // Check if still registered
      const isDoc = await doctorContract.doctors(addr);
      if (isDoc) {
        // Fetch profile
        const profile = await doctorContract.getDoctorProfile(addr);
        let publicKey = "";
        try {
          publicKey = await doctorContract.getDoctorPublicKey(addr);
        } catch {
          publicKey = "";
        }
        doctorsList.push({
          address: addr,
          name: profile[0],
          education: profile[1],
          license: profile[2],
          affiliatedComp: profile[3],
          phone: profile[4],
          gender: profile[5],
          title: profile[6],
          specialties: profile[7],
          publicKey
        });
      }
    }

    const container = $("registeredDoctorsList");
    if (container) {
      container.innerHTML = "";
      if (doctorsList.length === 0) {
        container.innerHTML = '<p class="muted">No registered doctors found.</p>';
      } else {
        for (const doc of doctorsList) {
          const row = document.createElement("div");
          row.className = "row";
          const btn = document.createElement("button");
          btn.type = "button";
          btn.textContent = `${doc.name} (${doc.title}) — ${doc.address.slice(0, 8)}…`;
          btn.addEventListener("click", () => {
            const authInput = $("patientDoctorAddress");
            if (authInput) authInput.value = doc.address;
            const readInput = $("doctorProfileReadAddress");
            if (readInput) readInput.value = doc.address;
            setStatus(`Doctor address filled: ${doc.address}`);
            Swal.fire({
              title: 'Doctor Profile',
              html: `<html>
                <div style="text-align:left">
                <p>Name:${doc.name}</p>
                <p>Title: ${doc.title}</p>
                <p>Education: ${doc.education}</p>
                <p>Specialties: ${doc.specialties}</p>
                <p>License: ${doc.license}</p>
                <p>AffiliatedComp: ${doc.affiliatedComp}</p>
                <p>Phone: ${doc.phone}</p>
                <p>Gender: ${doc.gender}</p>
                <p>Public Key: ${doc.publicKey || "(not set)"}</p>
                </div>
              </html>`,
              confirmButtonText: 'Close'
            });
          });
          row.appendChild(btn);
          container.appendChild(row);
        }
      }
    }
    setStatus(`Found ${doctorsList.length} registered doctor(s).`);
  } catch (e) {
    showError(e);
  }
}

async function registerDoctorRegistry() {
  try {
    if (!signer) throw new Error("Connect wallet first.");
    await makeDoctorContract(true);
    const name = $("d_name").value.trim();
    const education = $("d_education").value.trim();
    const license = $("d_license").value.trim();
    const affiliatedComp = ($("d_affiliates")?.value || "").trim();
    const title = $("d_title").value.trim();
    const specialties = ($("d_special")?.value || "").trim();
    const phone = ($("d_num")?.value || "").trim();
    const gender = getDoctorGender();
    const publicKey = ($("d_publicKey")?.value || "").trim();
    if (!name) throw new Error("Doctor name is required.");
    setStatus("Submitting registerDoctor...");
    const tx = await doctorContract.registerDoctor(name, education, license, affiliatedComp, title, phone, gender, specialties);
    await tx.wait();
    if (publicKey) {
      try {
        setStatus("Submitting doctor public key...");
        const txKey = await doctorContract.setDoctorPublicKey(publicKey);
        await txKey.wait();
        setStatus("You are registered as a doctor on-chain and public key saved.");
      } catch (e) {
        const msg = e?.shortMessage || e?.message || String(e);
        if (/missing revert data|BAD_DATA|could not decode result data/i.test(msg)) {
          setStatus(
            "Doctor registered, but this DoctorRegistry deployment does not support on-chain public key yet. Redeploy the updated contract to use this feature."
          );
          return;
        }
        throw e;
      }
    } else {
      setStatus("You are registered as a doctor on-chain.");
    }
  } catch (e) {
    showError(e);
  }
}

async function updateDoctorRegistry() {
  try {
    if (!signer) throw new Error("Connect wallet first.");
    await makeDoctorContract(true);
    const name = $("d_name").value.trim();
    const education = $("d_education").value.trim();
    const license = $("d_license").value.trim();
    const affiliatedComp = ($("d_affiliates")?.value || "").trim();
    const title = $("d_title").value.trim();
    const specialties = ($("d_special")?.value || "").trim();
    const phone = ($("d_num")?.value || "").trim();
    const gender = getDoctorGender();
    const publicKey = ($("d_publicKey")?.value || "").trim();
    if (!name) throw new Error("Doctor name is required.");
    setStatus("Submitting updateDoctor...");
    const tx = await doctorContract.updateDoctor(name, education, license, affiliatedComp, title, phone, gender, specialties);
    await tx.wait();
    if (publicKey) {
      try {
        setStatus("Submitting doctor public key update...");
        const txKey = await doctorContract.setDoctorPublicKey(publicKey);
        await txKey.wait();
      } catch (e) {
        const msg = e?.shortMessage || e?.message || String(e);
        if (/missing revert data|BAD_DATA|could not decode result data/i.test(msg)) {
          setStatus(
            "Doctor profile updated, but this DoctorRegistry deployment does not support on-chain public key yet. Redeploy updated contract to enable it."
          );
          return;
        }
        throw e;
      }
    }
    setStatus("Doctor profile updated.");
  } catch (e) {
    showError(e);
  }
}

async function getDoctorProfileFromRegistry() {
  try {
    if (!signer) throw new Error("Connect wallet first.");
    await makeDoctorContract(true);
    const raw = $("doctorProfileReadAddress")?.value || "";
    const who = raw && ethers.isAddress(raw) ? raw : currentAccount;
    if (!ethers.isAddress(who)) throw new Error("Invalid doctor address.");
    const [name, education, license, affiliatedComp, phone, gender, title, specialties] = await doctorContract.getDoctorProfile(who);
    let publicKey = "";
    try {
      publicKey = await doctorContract.getDoctorPublicKey(who);
    } catch {
      publicKey = "";
    }
    const outD = $("profileOutput_D");
    if (outD) {
      outD.innerText = JSON.stringify(
        { name, education, license, affiliatedComp, phone, gender, title, specialties, publicKey },
        null,
        2
      );
    }
    setStatus("Doctor profile loaded (stored in plain text on-chain).");
  } catch (e) {
    showError(e);
  }
}

async function viewPatientAllergies() {
  await makeContract();
  requirePatientRegistryContract();
  const raw = ($("allergyReadPatientAddress")?.value || "");
  const patientAddress =
    raw && ethers.isAddress(raw) ? raw : currentAccount;
  if (!ethers.isAddress(patientAddress)) throw new Error("Invalid or missing patient address.");
  if (
    currentAccount.toLowerCase() !== patientAddress.toLowerCase() &&
    !(await isDoctorAuthorizedOnChain(currentAccount, patientAddress))
  ) {
    throw new Error("Access denied: this patient has not authorized your doctor wallet on-chain.");
  }
  setStatus("Reading allergies from chain...");
  const allergies = await contract.getAllergies(patientAddress);

  const out = [];
  for (const a of allergies) {
    try {
      const encryptedStr = a.encryptedAllergy;
      const recomputedHash = await sha256StringToHex32(encryptedStr);
      if (recomputedHash.toLowerCase() !== String(a.allergyHash).toLowerCase()) {
        out.push({ error: "Integrity check failed (allergyHash mismatch)." });
        continue;
      }
      const wrapper = JSON.parse(encryptedStr);
      const encForMe =
        currentAccount.toLowerCase() === patientAddress.toLowerCase()
          ? wrapper.patient
          : wrapper.doctor;

      const plaintext = await decryptWithMetaMask(encForMe);
      const payload = JSON.parse(plaintext);
      out.push(payload);
    } catch (err) {
      out.push({ error: "Failed to decrypt allergy item.", details: String(err) });
    }
  }

  $("allergiesOutput").innerText = JSON.stringify(out, null, 2);
  setStatus("Allergies decrypted using MetaMask.");
}

async function getAllergiesDecrypt() {
  try {
    await viewPatientAllergies();
  } catch (e) {
    showError(e);
  }
}

function toUnixTimestamp(datetimeLocalValue) {
  const ms = new Date(datetimeLocalValue).getTime();
  if (!Number.isFinite(ms) || ms <= 0) {
    throw new Error("Invalid appointment date/time.");
  }
  return Math.floor(ms / 1000);
}

function formatAppointmentTimestamp(ts) {
  const n = Number(ts);
  if (!n) return "-";
  return new Date(n * 1000).toLocaleString();
}

function appointmentStatusText(status) {
  const map = {
    0: "Requested",
    1: "Approved",
    2: "Rejected",
    3: "Completed",
    4: "Cancelled",
  };
  return map[Number(status)] ?? `Unknown(${String(status)})`;
}

async function createAppointment() {
  try {
    await makeContract();
    requirePatientRegistryContract();
    const doctor = ($("apptDoctorAddress")?.value || "").trim();
    const scheduledAtRaw = ($("apptScheduledAt")?.value || "").trim();
    const feeRaw = ($("apptFee")?.value || "").trim();
    const reason = ($("apptReason")?.value || "").trim();

    if (!ethers.isAddress(doctor)) throw new Error("Invalid doctor address.");
    if (!scheduledAtRaw || !feeRaw || !reason) throw new Error("Please fill in all appointment fields.");

    const scheduledAt = toUnixTimestamp(scheduledAtRaw);
    const fee = BigInt(feeRaw);
    if (fee <= 0n) throw new Error("Fee must be greater than zero.");

    setStatus("Submitting createAppointment...");
    const tx = await contract.createAppointment(doctor, scheduledAt, fee, reason);
    await tx.wait();
    setStatus("Appointment created.");
  } catch (e) {
    showError(e);
  }
}

async function getAppointmentById() {
  try {
    await makeContract();
    requirePatientRegistryContract();
    const appointmentId = ($("queryAppointmentId")?.value || "").trim();
    if (!appointmentId) throw new Error("Please enter appointment ID.");

    const appt = await contract.getAppointment(appointmentId);
    const output = [
      `Appointment ID: ${appt[0].toString()}`,
      `Patient: ${appt[1]}`,
      `Doctor: ${appt[2]}`,
      `Scheduled At: ${formatAppointmentTimestamp(appt[3])}`,
      `Fee: ${appt[4].toString()}`,
      `Reason: ${appt[5]}`,
      `Status: ${appointmentStatusText(appt[6])}`,
      `Settled: ${String(appt[7])}`,
    ].join("\n");

    const out = $("appointmentOutput");
    if (out) out.innerText = output;
    setStatus("Appointment loaded.");
  } catch (e) {
    showError(e);
  }
}

async function loadAppointmentsForCurrentDoctor() {
  try {
    await makeContract();
    requirePatientRegistryContract();
    if (!currentAccount) throw new Error("Connect wallet first.");

    setStatus("Loading appointments for connected doctor wallet...");
    const filter = contract.filters.AppointmentCreated(null, null, currentAccount);
    const head = await provider.getBlockNumber();
    const logs = await contract.queryFilter(filter, 0, head);

    if (!logs.length) {
      const out = $("doctorAppointmentIdsOutput");
      if (out) out.innerText = "No appointments found for this doctor address.";
      setStatus("No appointments found for this doctor.");
      return;
    }

    const rows = [];
    const seenIds = new Set();
    for (const log of logs) {
      const rawId = log.args?.appointmentId ?? log.args?.[0];
      if (rawId == null) continue;
      const appointmentId = rawId.toString();
      if (seenIds.has(appointmentId)) continue;
      seenIds.add(appointmentId);

      const appt = await contract.getAppointment(appointmentId);
      rows.push({
        appointmentId,
        patient: appt[1],
        scheduledAt: formatAppointmentTimestamp(appt[3]),
        statusText: appointmentStatusText(appt[6]),
      });
    }

    rows.sort((a, b) => {
      const aid = BigInt(a.appointmentId);
      const bid = BigInt(b.appointmentId);
      if (aid < bid) return -1;
      if (aid > bid) return 1;
      return 0;
    });

    const out = $("doctorAppointmentIdsOutput");
    if (out) {
      out.innerHTML = "";
      for (const rowData of rows) {
        const row = document.createElement("div");
        row.className = "row";
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = `#${rowData.appointmentId} · ${rowData.statusText} · ${rowData.scheduledAt} · ${rowData.patient.slice(0, 8)}…${rowData.patient.slice(-6)}`;
        btn.addEventListener("click", () => {
          const approveInput = $("doctorAppointmentId");
          if (approveInput) approveInput.value = rowData.appointmentId;
          const completeInput = $("recordAppointmentId");
          if (completeInput) completeInput.value = rowData.appointmentId;
          const queryInput = $("queryAppointmentId");
          if (queryInput) queryInput.value = rowData.appointmentId;
          setStatus(`Filled appointment ID: ${rowData.appointmentId}`);
        });
        row.appendChild(btn);
        out.appendChild(row);
      }
    }

    setStatus(`Found ${rows.length} appointment(s) for your doctor wallet.`);
  } catch (e) {
    showError(e);
  }
}

async function respondAppointment(approved) {
  try {
    await makeDoctorContract(true);
    requirePatientRegistryContract();
    const appointmentId = ($("doctorAppointmentId")?.value || "").trim();
    if (!appointmentId) throw new Error("Please enter appointment ID.");
    const registryAddr = await contract.getAddress();

    setStatus(`Submitting ${approved ? "approve" : "reject"} appointment...`);
    const tx = await doctorContract.respondAppointment(registryAddr, appointmentId, approved);
    await tx.wait();
    setStatus(`Appointment ${approved ? "approved" : "rejected"}.`);
  } catch (e) {
    showError(e);
  }
}

async function completeAppointmentAndAddRecord() {
  try {
    await makeDoctorContract(true);
    requirePatientRegistryContract();
    const appointmentId = ($("recordAppointmentId")?.value || "").trim();
    if (!appointmentId) throw new Error("Please enter appointment ID.");

    const appt = await contract.getAppointment(appointmentId);
    const patientAddress = appt[1];
    const doctorAddress = appt[2];
    const status = Number(appt[6]);
    if (status !== 1) throw new Error("Appointment must be approved before completion.");
    if (doctorAddress.toLowerCase() !== currentAccount.toLowerCase()) {
      throw new Error("You are not the assigned doctor.");
    }

    const diagnosis = ($("recordD")?.value || "").trim();
    const prescription = ($("recordP")?.value || "").trim();
    const notes = ($("recordN")?.value || "").trim();
    const plaintextLegacy = ($("recordPlaintext")?.value || "").trim();
    const recordObj = plaintextLegacy
      ? { notes: plaintextLegacy }
      : { diagnosis, prescription, notes };
    if (!recordObj.notes && !recordObj.diagnosis && !recordObj.prescription) {
      throw new Error("Enter medical record content.");
    }

    const pastedPk = (($("recordPatientEncryptionPubKey")?.value || "").trim() ||
      ($("patientPublicKey")?.value || "").trim());
    const { encryptedDataString, contentHash } = await encryptMedicalRecordForChain(
      patientAddress,
      recordObj,
      pastedPk
    );
    const registryAddr = await contract.getAddress();
    setStatus("Submitting appointment completion and medical record...");
    const tx = await doctorContract.completeAppointmentAndAddMedicalRecord(
      registryAddr,
      appointmentId,
      contentHash,
      encryptedDataString
    );
    await tx.wait();
    setStatus("Appointment completed, payment settled, record added.");
  } catch (e) {
    showError(e);
  }
}

async function grantInitialCoinsForPatient() {
  try {
    await makeDoctorContract(true);
    requirePatientRegistryContract();
    const patientAddress = ($("grantPatientAddress")?.value || "").trim();
    const amountRaw = ($("grantAmount")?.value || "").trim();
    if (!ethers.isAddress(patientAddress)) throw new Error("Invalid patient address.");
    if (!amountRaw) throw new Error("Please enter amount.");
    const amount = BigInt(amountRaw);
    if (amount <= 0n) throw new Error("Amount must be greater than zero.");
    const registryAddr = await contract.getAddress();
    setStatus("Submitting initial coin grant...");
    const tx = await doctorContract.grantPatientInitialCoins(registryAddr, patientAddress, amount);
    await tx.wait();
    setStatus("Initial coins granted.");
  } catch (e) {
    showError(e);
  }
}

async function loadMyBalance() {
  try {
    await makeContract();
    requirePatientRegistryContract();
    const balance = await contract.getMyBalance();
    const out = $("myBalanceOutput");
    if (out) out.innerText = `My Balance: ${balance.toString()} coins`;
    setStatus("Balance loaded.");
  } catch (e) {
    showError(e);
  }
}

function wireDoctorRegistryAddressSync() {
  const ids = ["doctorRegistryAddress", "doctorRegistryAddressPanel"].filter((id) => $(id));
  for (const id of ids) {
    const el = $(id);
    if (!el) continue;
    el.addEventListener("input", () => {
      const v = el.value;
      for (const other of ids) {
        const o = $(other);
        if (o && other !== id) o.value = v;
      }
    });
  }
}

function wireAddressFieldNormalization() {
  const addressFieldIds = [
    "contractAddress",
    "doctorRegistryAddress",
    "doctorRegistryAddressPanel",
    "patientDoctorAddress",
    "profileReadPatientAddress",
    "recordPatientAddress",
    "readPatientAddress",
    "allergyPatientAddressDr",
    "allergyReadPatientAddress",
    "doctorProfileReadAddress",
  ];
}

function LinkUI() {
  const onClick = (id, handler) => {
    const el = $(id);
    if (!el) {
      console.warn(`Missing element #${id}; handler not attached.`);
      return;
    }
    el.addEventListener("click", handler);
  };

  wireDoctorRegistryAddressSync();
  wireAddressFieldNormalization();

  if (window.ethereum?.on) {
    window.ethereum.on("chainChanged", () => {
      if (!window.ethereum) return;
      provider = new ethers.BrowserProvider(window.ethereum);
      refreshNetworkLabel().catch(() => {});
      setStatus("Network changed in MetaMask. If chainId no longer matches Ganache/Truffle, switch back or reconnect.");
    });
  }

  onClick("connectBtn", async () => {
    try {
      await connectWallet();
      await makeContract();
      await detectRoleFromContract();
    } catch (e) {
      showError(e);
    }
  });

  onClick("choosePatientBtn", () => {
    showPanelByRole("patient");
    setStatus("Selected role: Patient. Register / Update your profile.");
  });

  onClick("chooseDoctorBtn", () => {
    showPanelByRole("doctor");
    setStatus("Selected role: Doctor. Add records for registered patients.");
  });

  onClick("registerPatientBtn", registerPatient);
  onClick("updateProfileBtn", updateProfile);
  onClick("getMyProfilePatientBtn", getMyProfileDecrypted);
  onClick("showEncryptionPubKeyBtn", showMyEncryptionPublicKeyForDoctor);
  onClick("getMyProfileDoctorBtn", getDoctorProfileFromRegistry);

  onClick("addMedicalRecordBtn", addMedicalRecord);
  onClick("getMedicalRecordsBtn", getMedicalRecordsDecryptAndVerify);
  onClick("loadAuthorizedPatientsBtn", loadAuthorizedPatientsForDoctor);
  onClick("loadRegisteredDoctorsBtn", loadRegisteredDoctors);

  onClick("addAllergyViaDoctorRegistryBtn", addAllergyViaDoctorRegistry);
  onClick("getAllergiesBtn", getAllergiesDecrypt);
  onClick("btnCreateAppointment", createAppointment);
  onClick("btnQueryAppointment", getAppointmentById);
  onClick("btnLoadDoctorAppointments", loadAppointmentsForCurrentDoctor);
  onClick("btnApproveAppointment", () => respondAppointment(true));
  onClick("btnRejectAppointment", () => respondAppointment(false));
  onClick("btnCompleteAppointmentRecord", completeAppointmentAndAddRecord);
  onClick("btnGrantCoins", grantInitialCoinsForPatient);
  onClick("btnLoadMyBalance", loadMyBalance);

  onClick("registerDoctorBtn", registerDoctorRegistry);
  onClick("updateDoctorProfileBtn", updateDoctorRegistry);

  onClick("authorizeDoctorBtn", async () => {
    try {
      await makeContract();
      requirePatientRegistryContract();
      const doctorAddress = $("patientDoctorAddress").value || "";
      if (!ethers.isAddress(doctorAddress)) throw new Error("Invalid doctor address.");
      const authorized = $("patientDoctorAuthorized").value === "true";
      if (!currentAccount) throw new Error("Connect wallet first.");
      setStatus("Submitting setDoctorAuthorization (on-chain)...");
      const tx = await contract.setDoctorAuthorization(doctorAddress, authorized);
      await tx.wait();
      setStatus("Doctor authorization updated on-chain for your patient account.");
    } catch (e) {
      showError(e);
    }
  });
}

LinkUI();
showPanelByRole("unknown");



