const {
  bsv,
  buildContractClass,
  getPreimage,
  toHex,
  num2bin,
  Bytes,
  signTx,
  PubKey,
  SigHashPreimage,
  Sig
} = require('scryptlib');
const {
  DataLen,
  loadDesc,
  createLockingTx,
  sendTx,
  reverseEndian,
  showError
} = require('../helper');
const {
  privateKey
} = require('../privateKey');

(async () => {
  const privateKey1 = new bsv.PrivateKey.fromRandom('testnet')
  const publicKey1 = bsv.PublicKey.fromPrivateKey(privateKey1)
  const privateKey2 = new bsv.PrivateKey.fromRandom('testnet')
  const publicKey2 = bsv.PublicKey.fromPrivateKey(privateKey2)
  const privateKey3 = new bsv.PrivateKey.fromRandom('testnet')
  const publicKey3 = bsv.PublicKey.fromPrivateKey(privateKey3)

  try {
    const BitcoinToken = buildContractClass(loadDesc('bitcoin_desc.json'))
    const bitcoinToken = new BitcoinToken()

    // append state as passive data part
    // initial token supply 100: publicKey1 has 100, publicKey2 0
    bitcoinToken.setDataPart(toHex(publicKey1) + num2bin(10, DataLen) + num2bin(90, DataLen))

    let inputSatoshis = 10000
    const FEE = inputSatoshis / 4
    let outputAmount = Math.floor((inputSatoshis - FEE) / 2)

    // lock fund to the script
    const lockingTx = await createLockingTx(privateKey.toAddress(), inputSatoshis, FEE)
    lockingTx.outputs[0].setScript(bitcoinToken.lockingScript)
    lockingTx.sign(privateKey)
    let lockingTxid = await sendTx(lockingTx)
    console.log('funding txid:      ', lockingTxid)

    // split one UTXO of 100 tokens into one with 70 tokens and one with 30
    let splitTxid, lockingScript0, lockingScript1 
    {
      const tx = new bsv.Transaction()
      tx.addInput(new bsv.Transaction.Input({
        prevTxId: lockingTxid,
        outputIndex: 0,
        script: ''
      }), bitcoinToken.lockingScript, inputSatoshis)

      lockingScript0 = [bitcoinToken.codePart.toASM(), toHex(publicKey2) + num2bin(0, DataLen) + num2bin(70, DataLen)].join(' ')
      tx.addOutput(new bsv.Transaction.Output({
        script: bsv.Script.fromASM(lockingScript0),
        satoshis: outputAmount
      }))
      lockingScript1 = [bitcoinToken.codePart.toASM(), toHex(publicKey3) + num2bin(0, DataLen) + num2bin(30, DataLen)].join(' ')
      tx.addOutput(new bsv.Transaction.Output({
        script: bsv.Script.fromASM(lockingScript1),
        satoshis: outputAmount
      }))

      const preimage = getPreimage(tx, bitcoinToken.lockingScript.toASM(), inputSatoshis)
      const sig1 = signTx(tx, privateKey1, bitcoinToken.lockingScript.toASM(), inputSatoshis)
      const unlockingScript = bitcoinToken.split(
        new Sig(toHex(sig1)),
        new PubKey(toHex(publicKey2)),
        70,
        outputAmount,
        new PubKey(toHex(publicKey3)),
        30,
        outputAmount,
        new SigHashPreimage(toHex(preimage))
      ).toScript()
      tx.inputs[0].setScript(unlockingScript);
      splitTxid = await sendTx(tx);
      console.log('split txid:       ', splitTxid)
    }

    inputSatoshis = outputAmount
    outputAmount -= FEE
    // merge one UTXO with 70 tokens and one with 30 into a single UTXO of 100 tokens
    {
      const tx = new bsv.Transaction()
      tx.addInput(new bsv.Transaction.Input({
        prevTxId: splitTxid,
        outputIndex: 0,
        script: ''
      }), bsv.Script.fromASM(lockingScript0), inputSatoshis)

      tx.addInput(new bsv.Transaction.Input({
        prevTxId: splitTxid,
        outputIndex: 1,
        script: ''
      }), bsv.Script.fromASM(lockingScript1), inputSatoshis)

      const lockingScript2 = [bitcoinToken.codePart.toASM(), toHex(publicKey1) + num2bin(70, DataLen) + num2bin(30, DataLen)].join(' ')
      tx.addOutput(new bsv.Transaction.Output({
        script: bsv.Script.fromASM(lockingScript2),
        satoshis: outputAmount
      }))

      // use reversed txid in outpoint
      const txHash = reverseEndian(splitTxid)
      const prevouts = txHash + num2bin(0, 4) + txHash + num2bin(1, 4)

      // input 0
      {
        const preimage = getPreimage(tx, lockingScript0, inputSatoshis, 0)
        const sig2 = signTx(tx, privateKey2, lockingScript0, inputSatoshis, 0)
        const unlockingScript = bitcoinToken.merge(
          new Sig(toHex(sig2)),
          new PubKey(toHex(publicKey1)),
          new Bytes(prevouts), 30, outputAmount,
          new SigHashPreimage(toHex(preimage))
        ).toScript()
        tx.inputs[0].setScript(unlockingScript);
      }

      // input 1
      {
        const preimage = getPreimage(tx, lockingScript1, inputSatoshis, 1)
        const sig3 = signTx(tx, privateKey3, lockingScript1, inputSatoshis, 1)
        const unlockingScript = bitcoinToken.merge(
          new Sig(toHex(sig3)),
          new PubKey(toHex(publicKey1)),
          new Bytes(prevouts), 70, outputAmount,
          new SigHashPreimage(toHex(preimage))
        ).toScript()
        tx.inputs[1].setScript(unlockingScript);
      }

      const mergeTxid = await sendTx(tx);
      console.log('merge txid:       ', mergeTxid)
    }

    console.log('Succeeded on testnet')
  } catch (error) {
    console.log('Failed on testnet')
    showError(error)
  }
})()