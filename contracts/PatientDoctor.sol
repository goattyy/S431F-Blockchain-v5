// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

contract PatientRegistry {
    // patient => doctor => whether this patient authorized this doctor
    mapping(address => mapping(address => bool)) public patientDoctorAuthorized;
    mapping(address => bool) public patients;

    // Basic info (ciphertext + integrity hash only)
    struct Patient {
        string encryptedInfo;
        bytes32 profileHash;
    }

    // Medical record
    struct MedicalRecord {
        uint256 recordId;
        uint256 date;
        bytes32 contentHash;
        string encryptedData;
        string doctorName;
        address doctorAddress;
    }

    // Allergies
    struct Allergy {
        string encryptedAllergy;
        bytes32 allergyHash;
    }

    enum AppointmentStatus {
        Requested,
        Approved,
        Rejected,
        Completed,
        Cancelled
    }

    struct Appointment {
        uint256 id;
        address patient;
        address doctor;
        uint256 scheduledAt;
        uint256 fee;
        string reason;
        AppointmentStatus status;
        bool settled;
    }
    
    
    mapping(address => Patient) private profiles;
    mapping(address => MedicalRecord[]) private medicalHistory;
    mapping(address => Allergy[]) private allergyHistory;
    mapping(address => uint256) public balances;
    mapping(uint256 => Appointment) public appointments;
    uint256 public nextAppointmentId = 1;

    address public trustedDoctorRegistry;
    address private _deployer;

    // Logging
    event DoctorAuthorizationUpdated(address indexed patient, address indexed doctor, bool authorized);
    event PatientRegistered(address indexed patient);
    event ProfileUpdated(address indexed patient);
    event MedicalRecordAdded(
        address indexed patient,
        uint256 indexed recordId,
        bytes32 indexed contentHash,
        uint256 date
    );
    event AllergyAdded(address indexed patient, bytes32 allergyHash);
    event CoinsGranted(address indexed patient, uint256 amount);
    event CoinsTransferred(address indexed from, address indexed to, uint256 amount);
    event AppointmentCreated(
        uint256 indexed appointmentId,
        address indexed patient,
        address indexed doctor,
        uint256 scheduledAt,
        uint256 fee,
        string reason
    );
    event AppointmentResponded(
        uint256 indexed appointmentId,
        address indexed doctor,
        AppointmentStatus status
    );
    event AppointmentCancelled(uint256 indexed appointmentId, address indexed patient);
    event AppointmentCompleted(
        uint256 indexed appointmentId,
        address indexed patient,
        address indexed doctor,
        uint256 fee
    );

    constructor() {
        _deployer = msg.sender;
    }

    function setTrustedDoctorRegistry(address registry) external {
        require(msg.sender == _deployer, "Only deployer");
        require(registry != address(0) && trustedDoctorRegistry == address(0), "Bad args or already set");
        trustedDoctorRegistry = registry;
    }

    modifier onlyPatient() {
        require(patients[msg.sender], "Only registered patient");
        _;
    }

    // Verify access right
    modifier onlyAuthorizedDoctorOrSelf(address patientAddress) {
        require(
            msg.sender == patientAddress || patientDoctorAuthorized[patientAddress][msg.sender],
            "Not authorized"
        );
        _;
    }

    modifier patientExists(address patientAddress) {
        require(patients[patientAddress], "Patient not registered");
        _;
    }

    // DoctorAuthorization
    function setDoctorAuthorization(address doctor, bool authorized) external onlyPatient {
        require(doctor != address(0), "Invalid doctor address");
        patientDoctorAuthorized[msg.sender][doctor] = authorized;
        emit DoctorAuthorizationUpdated(msg.sender, doctor, authorized);
    }

    function grantInitialCoins(address patient, uint256 amount) external {
        require(msg.sender == trustedDoctorRegistry, "Only DoctorRegistry");
        require(patients[patient], "Patient not registered");
        balances[patient] += amount;
        emit CoinsGranted(patient, amount);
    }

    function getMyBalance() external view returns (uint256) {
        return balances[msg.sender];
    }

    function registerPatient(string memory encryptedInfo, bytes32 profileHash) public {
        require(!patients[msg.sender], "Already registered as patient!");
        require(bytes(encryptedInfo).length > 0, "Encrypted info required");
        require(profileHash != bytes32(0), "Invalid profile hash");

        patients[msg.sender] = true;
        profiles[msg.sender] = Patient({encryptedInfo: encryptedInfo, profileHash: profileHash});

        emit PatientRegistered(msg.sender);
    }

    function updateProfile(string memory encryptedInfo, bytes32 profileHash) public onlyPatient {
        require(bytes(encryptedInfo).length > 0, "Encrypted info required");
        require(profileHash != bytes32(0), "Invalid profile hash");

        Patient storage profile = profiles[msg.sender];
        profile.encryptedInfo = encryptedInfo;
        profile.profileHash = profileHash;

        emit ProfileUpdated(msg.sender);
    }

    function createAppointment(
        address doctor,
        uint256 scheduledAt,
        uint256 fee,
        string memory reason
    ) external onlyPatient returns (uint256) {
        require(doctor != address(0), "Invalid doctor");
        require(scheduledAt > block.timestamp, "Time must be in future");
        require(fee > 0, "Fee must be > 0");

        uint256 appointmentId = nextAppointmentId++;
        appointments[appointmentId] = Appointment({
            id: appointmentId,
            patient: msg.sender,
            doctor: doctor,
            scheduledAt: scheduledAt,
            fee: fee,
            reason: reason,
            status: AppointmentStatus.Requested,
            settled: false
        });

        emit AppointmentCreated(appointmentId, msg.sender, doctor, scheduledAt, fee, reason);
        return appointmentId;
    }

    function cancelAppointment(uint256 appointmentId) external {
        Appointment storage appt = appointments[appointmentId];
        require(appt.patient == msg.sender, "Not your appointment");
        require(
            appt.status == AppointmentStatus.Requested || appt.status == AppointmentStatus.Approved,
            "Cannot cancel now"
        );

        appt.status = AppointmentStatus.Cancelled;
        emit AppointmentCancelled(appointmentId, msg.sender);
    }

    function respondAppointmentByDoctor(uint256 appointmentId, bool approved) external {
        require(msg.sender == trustedDoctorRegistry, "Only DoctorRegistry");
        Appointment storage appt = appointments[appointmentId];
        require(appt.id != 0, "Appointment not found");
        require(appt.status == AppointmentStatus.Requested, "Appointment already handled");

        if (approved) {
            appt.status = AppointmentStatus.Approved;
        } else {
            appt.status = AppointmentStatus.Rejected;
        }

        emit AppointmentResponded(appointmentId, appt.doctor, appt.status);
    }

    function completeAppointmentAndAddRecordByDoctor(
        uint256 appointmentId,
        address doctorWallet,
        bytes32 contentHash,
        string memory encryptedData,
        string memory doctorName
    ) external {
        require(msg.sender == trustedDoctorRegistry, "Only DoctorRegistry");
        Appointment storage appt = appointments[appointmentId];
        require(appt.id != 0, "Appointment not found");
        require(appt.status == AppointmentStatus.Approved, "Appointment not approved");
        require(!appt.settled, "Appointment already settled");
        require(appt.doctor == doctorWallet, "Doctor mismatch");
        require(patientDoctorAuthorized[appt.patient][doctorWallet], "Doctor not authorized");
        require(balances[appt.patient] >= appt.fee, "Insufficient patient coins");
        require(contentHash != bytes32(0), "Invalid content hash");
        require(bytes(encryptedData).length > 0, "Encrypted payload required");
        require(bytes(doctorName).length > 0, "Doctor name required");

        balances[appt.patient] -= appt.fee;
        balances[appt.doctor] += appt.fee;
        appt.settled = true;
        appt.status = AppointmentStatus.Completed;

        uint256 recordId = medicalHistory[appt.patient].length;
        medicalHistory[appt.patient].push(
            MedicalRecord({
                recordId: recordId,
                date: block.timestamp,
                contentHash: contentHash,
                encryptedData: encryptedData,
                doctorName: doctorName,
                doctorAddress: doctorWallet
            })
        );

        emit CoinsTransferred(appt.patient, appt.doctor, appt.fee);
        emit AppointmentCompleted(appointmentId, appt.patient, appt.doctor, appt.fee);
        emit MedicalRecordAdded(appt.patient, recordId, contentHash, block.timestamp);
    }

    // Only authorized doctor
    function addMedicalRecordForAuthorizedDoctor(
        address patientAddress,
        address doctorWallet,
        bytes32 contentHash,
        string memory encryptedData,
        string memory doctorName
    ) external patientExists(patientAddress) {
        require(trustedDoctorRegistry != address(0), "PatientRegistry: link DoctorRegistry via setTrustedDoctorRegistry");
        require(msg.sender == trustedDoctorRegistry, "Only DoctorRegistry");
        require(patientDoctorAuthorized[patientAddress][doctorWallet], "Doctor not authorized for this patient");
        require(contentHash != bytes32(0), "Invalid content hash");
        require(bytes(encryptedData).length > 0, "Encrypted payload URI required");
        require(bytes(doctorName).length > 0, "Doctor name required");

        uint256 recordId = medicalHistory[patientAddress].length;
        medicalHistory[patientAddress].push(
            MedicalRecord({
                recordId: recordId,
                date: block.timestamp,
                contentHash: contentHash,
                encryptedData: encryptedData,
                doctorName: doctorName,
                doctorAddress: doctorWallet
            })
        );

        emit MedicalRecordAdded(patientAddress, recordId, contentHash, block.timestamp);
    }


    // Must be authorized by the patient
    function addAllergyForAuthorizedDoctor(
        address patientAddress,
        address doctorWallet,
        string memory encryptedAllergy,
        bytes32 allergyHash
    ) external patientExists(patientAddress) {
        require(trustedDoctorRegistry != address(0), "PatientRegistry: link DoctorRegistry via setTrustedDoctorRegistry");
        require(msg.sender == trustedDoctorRegistry, "Only DoctorRegistry");
        require(patientDoctorAuthorized[patientAddress][doctorWallet], "Not authorized");
        require(bytes(encryptedAllergy).length > 0, "Encrypted allergy required");
        require(allergyHash != bytes32(0), "Invalid allergy hash");

        allergyHistory[patientAddress].push(
            Allergy({encryptedAllergy: encryptedAllergy, allergyHash: allergyHash})
        );

        emit AllergyAdded(patientAddress, allergyHash);
    }

    function getMyProfile(
        address patientAddress
    )
        external
        view
        patientExists(patientAddress)
        onlyAuthorizedDoctorOrSelf(patientAddress)
        returns (string memory encryptedInfo, bytes32 profileHash)
    {
        Patient storage p = profiles[patientAddress];
        return (p.encryptedInfo, p.profileHash);
    }

    function getMedicalRecord(
        address patientAddress
    ) external view patientExists(patientAddress) onlyAuthorizedDoctorOrSelf(patientAddress) returns (MedicalRecord[] memory) {
        return medicalHistory[patientAddress];
    }

    function getAllergies(
        address patientAddress
    ) external view patientExists(patientAddress) onlyAuthorizedDoctorOrSelf(patientAddress) returns (Allergy[] memory) {
        return allergyHistory[patientAddress];
    }

    function getAppointment(
        uint256 appointmentId
    )
        external
        view
        returns (
            uint256 id,
            address patient,
            address doctor,
            uint256 scheduledAt,
            uint256 fee,
            string memory reason,
            AppointmentStatus status,
            bool settled
        )
    {
        Appointment memory appt = appointments[appointmentId];
        require(appt.id != 0, "Appointment not found");
        require(msg.sender == appt.patient || msg.sender == appt.doctor, "Not authorized");
        return (
            appt.id,
            appt.patient,
            appt.doctor,
            appt.scheduledAt,
            appt.fee,
            appt.reason,
            appt.status,
            appt.settled
        );
    }
}

contract DoctorRegistry {
    // Basic info
    struct Doctor {
        string name;
        string education;
        string license;
        string affiliatedComp;
        string phone;
        string gender;
        string title;
        string specialties;
        string encryptionPublicKey;
    }

    mapping(address => Doctor) private profiles;
    mapping(address => bool) public doctors;

    modifier onlyRegisteredDoctor() {
        require(doctors[msg.sender], "Only registered doctor");
        _;
    }
    // Logging
    event DoctorRegistered(address indexed doctor);
    event DoctorUpdated(address indexed doctor);
    event DoctorPublicKeyUpdated(address indexed doctor);

    function registerDoctor(
        string memory name,
        string memory education,
        string memory license,
        string memory affiliatedComp,
        string memory title,
        string memory phone,
        string memory gender,
        string memory specialties
    ) public {
        require(!doctors[msg.sender], "Already registered as doctor!");
        require(bytes(name).length > 0, "Name required");
        doctors[msg.sender] = true;
        profiles[msg.sender] = Doctor({
            name: name,
            education: education,
            license: license,
            affiliatedComp: affiliatedComp,
            title: title,
            phone: phone,
            gender: gender,
            specialties: specialties,
            encryptionPublicKey: ""
        });
        emit DoctorRegistered(msg.sender);
    }

    function updateDoctor(
        string memory name,
        string memory education,
        string memory license,
        string memory affiliatedComp,
        string memory title,
        string memory phone,
        string memory gender,
        string memory specialties
    ) public onlyRegisteredDoctor {
        require(bytes(name).length > 0, "Name required");
        Doctor storage profile = profiles[msg.sender];
        profile.name = name;
        profile.education = education;
        profile.license = license;
        profile.affiliatedComp = affiliatedComp;
        profile.title = title;
        profile.phone = phone;
        profile.gender = gender;
        profile.specialties = specialties;
        emit DoctorUpdated(msg.sender);
    }

    function getDoctorProfile(
        address doctorAddress
    )
        external
        view
        returns (
            string memory name,
            string memory education,
            string memory license,
            string memory affiliatedComp,
            string memory phone,
            string memory gender,
            string memory title,
            string memory specialties
        )
    {
        require(doctors[doctorAddress], "Doctor not found!");
        Doctor storage profile = profiles[doctorAddress];
        return (
            profile.name,
            profile.education,
            profile.license,
            profile.affiliatedComp,
            profile.title,
            profile.phone,
            profile.gender,
            profile.specialties
        );
    }

    function setDoctorPublicKey(string memory encryptionPublicKey) external onlyRegisteredDoctor {
        require(bytes(encryptionPublicKey).length > 0, "Public key required");
        profiles[msg.sender].encryptionPublicKey = encryptionPublicKey;
        emit DoctorPublicKeyUpdated(msg.sender);
    }

    function getDoctorPublicKey(address doctorAddress) external view returns (string memory) {
        require(doctors[doctorAddress], "Doctor not found!");
        return profiles[doctorAddress].encryptionPublicKey;
    }

    // Registered doctor adds record for patient with authorization
    function addMedicalRecordByDoctor(
        PatientRegistry registry,
        address patientAddress,
        bytes32 contentHash,
        string memory encryptedData
    ) public onlyRegisteredDoctor {
        require(registry.patients(patientAddress), "Patient not registered");
        require(registry.patientDoctorAuthorized(patientAddress, msg.sender), "Not authorized for this patient");
        string memory doctorName = profiles[msg.sender].name;
        registry.addMedicalRecordForAuthorizedDoctor(patientAddress, msg.sender, contentHash, encryptedData, doctorName);
    }

    // Registered doctor adds record for patient with authorization
    function addAllergyByDoctor(
        PatientRegistry registry,
        address patientAddress,
        string memory encryptedAllergy,
        bytes32 allergyHash
    ) public onlyRegisteredDoctor {
        require(registry.patients(patientAddress), "Patient not registered");
        require(registry.patientDoctorAuthorized(patientAddress, msg.sender), "Not authorized for this patient");
        registry.addAllergyForAuthorizedDoctor(patientAddress, msg.sender, encryptedAllergy, allergyHash);
    }

    function respondAppointment(
        PatientRegistry registry,
        uint256 appointmentId,
        bool approved
    ) external onlyRegisteredDoctor {
        (
            uint256 id,
            ,
            address doctor,
            ,
            ,
            ,
            ,
        ) = registry.appointments(appointmentId);

        require(id != 0, "Appointment not found");
        require(doctor == msg.sender, "Not assigned doctor");
        registry.respondAppointmentByDoctor(appointmentId, approved);
    }

    function completeAppointmentAndAddMedicalRecord(
        PatientRegistry registry,
        uint256 appointmentId,
        bytes32 contentHash,
        string memory encryptedData
    ) external onlyRegisteredDoctor {
        (
            uint256 id,
            ,
            address doctor,
            ,
            ,
            ,
            ,
        ) = registry.appointments(appointmentId);

        require(id != 0, "Appointment not found");
        require(doctor == msg.sender, "Not assigned doctor");
        string memory doctorName = profiles[msg.sender].name;
        registry.completeAppointmentAndAddRecordByDoctor(
            appointmentId,
            msg.sender,
            contentHash,
            encryptedData,
            doctorName
        );
    }

    function grantPatientInitialCoins(
        PatientRegistry registry,
        address patient,
        uint256 amount
    ) external {
        registry.grantInitialCoins(patient, amount);
    }
}
