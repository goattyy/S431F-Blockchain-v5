// truffle-config.js
module.exports = {
  compilers: {
    solc: {
      version: "0.8.19",
      settings: {
        optimizer: { enabled: true, runs: 200 },
      },
    },
  },
  networks: {
    // For Ganache GUI (port 7545)
    development: {
      host: "127.0.0.1",
      port: 7545,      // ← Must match Ganache GUI port
      network_id: "*"  // ← Must match Ganache network ID
    },
    
    // For Ganache CLI (port 8545)
    ganache: {
      host: "127.0.0.1",
      port: 8545,      // ← Must match Ganache CLI port
      network_id: "*"  // Or specific ID like 1337
    }
  }
};
