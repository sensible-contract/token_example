const { exit } = require('process')
const { bsv } = require('scryptlib');

// fill in private key on testnet in WIF here
const privateKeyA = new bsv.PrivateKey.fromWIF("cSvsnrjfdimWwTqMoSyGhMr5QaEv8ivZKBWGjU6zJGJYnNAsrLAd");
const privateKeyB = new bsv.PrivateKey.fromWIF("cSpXSiegNWNQnZZaLX37rWepu1qxWg75kgqDsoEpyS3rwEpYtnku");
const key = 'cPbFsSjFjCbfzTRc8M4nKNGhVJspwnPQAcDhdJgVr3Pdwpqq7LfA'

if (!key) {
  genPrivKey()
}

function genPrivKey() {
  const newPrivKey = new bsv.PrivateKey.fromRandom('testnet')
  console.log(`Missing private key, generating a new one ...
Private key generated: '${newPrivKey.toWIF()}'
You can fund its address '${newPrivKey.toAddress()}' from some faucet and use it to complete the test
Example faucets are https://faucet.bitcoincloud.net and https://testnet.satoshisvision.network`)
  exit(0)
}

const privateKey = new bsv.PrivateKey.fromWIF(key)

module.exports = {
  privateKey,
  genPrivKey
}
