var PatientRegistry = artifacts.require("PatientRegistry");
var DoctorRegistry = artifacts.require("DoctorRegistry");

module.exports = function (deployer) {
  return deployer
    .deploy(PatientRegistry)
    .then(function () {
      return deployer.deploy(DoctorRegistry);
    })
    .then(async function () {
      const pr = await PatientRegistry.deployed();
      const dr = await DoctorRegistry.deployed();
      await pr.setTrustedDoctorRegistry(dr.address);
    });
};
