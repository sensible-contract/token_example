const { bsv, buildContractClass, signTx, toHex, getPreimage, num2bin, Ripemd160, PubKey, SigHashPreimage, Sig, Bytes } = require("scryptlib");
const { inputIndex, compileContract, DataLen, dummyTxId, satoTxSigUTXOSpendBy, satoTxSigUTXO, reverseEndian } = require("../helper");

// const { privateKey } = require("../privateKey");
const dummyPrivKey = new bsv.PrivateKey.fromWIF("cPbFsSjFjCbfzTRc8M4nKNGhVJspwnPQAcDhdJgVr3Pdwpqq7LfA");
const dummyPk = bsv.PublicKey.fromPrivateKey(dummyPrivKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPk.toBuffer());

const dummyInputSatoshis = 100001000;
const dummyOutputSatoshis = 100000000;
const dummyChangeSatoshis = 10000;

const Signature = bsv.crypto.Signature;
// Note: ANYONECANPAY
const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

const DataLen8 = 8;
const DataLen4 = 4;

const ISSUE = "00";
const TRANSFER = "01";
const SWAP = "02";
const SELL = "03";

const TokenContractClass = buildContractClass(compileContract("nft.scrypt"));

/**
 * Create new Tx by inputs and outputs
 *
 * {
 *   inputs: {
 *     txid: "xx",
 *     vout: 0,
 *     satoshis: 32,
 *     script: "xx"
 *   },
 *   outputs: {
 *     satoshis: 32,
 *     script: "xx"
 *     to: "xx"
 *   }
 * }
 */
function makeTx({ inputs, outputs } = {}) {
  let txnew = new bsv.Transaction();
  inputs.forEach((input) => {
    var script;
    if (input.to) {
      script = bsv.Script.buildPublicKeyHashOut(input.to);
    } else if (input.script) {
      script = bsv.Script.fromASM(input.script);
    }
    txnew.addInput(new bsv.Transaction.Input({ prevTxId: input.txid, outputIndex: input.vout, script: "" }), script, input.satoshis);
  });

  outputs.forEach((output) => {
    var script;
    if (output.to) {
      script = bsv.Script.buildPublicKeyHashOut(output.to);
    } else if (output.script) {
      script = bsv.Script.fromASM(output.script);
    }
    txnew.addOutput(new bsv.Transaction.Output({ script: script, satoshis: output.satoshis }));
  });
  return txnew;
}

class NFT {
  constructor(rabinPubKey) {
    this.token = new TokenContractClass(rabinPubKey);
    this.codePart = this.token.codePart.toASM();
  }

  // start
  makeTxP2pk({ inputSatoshis, outputSatoshis } = {}) {
    let txnew = makeTx({
      inputs: [
        {
          txid: dummyTxId,
          vout: 0,
          satoshis: inputSatoshis,
          to: dummyPk,
        },
      ],
      outputs: [
        {
          satoshis: outputSatoshis,
          to: dummyPk,
        },
      ],
    });
    return txnew;
  }

  // Genesis
  makeTxGenesis({ prevTxId, outputIndex, thisIssuerPkh, lastTokenId, inputSatoshis, genesisSatoshis } = {}) {
    this.genesisPart = reverseEndian(prevTxId) + num2bin(outputIndex, DataLen4) + num2bin(0, DataLen4);
    const newLockingScript = [this.codePart, this.genesisPart, toHex(thisIssuerPkh) + num2bin(lastTokenId, DataLen8) + ISSUE].join(" ");

    let txnew = makeTx({
      inputs: [
        {
          txid: prevTxId, // genesis utxo
          vout: outputIndex,
          satoshis: inputSatoshis,
          to: dummyPk,
        },
      ],
      outputs: [
        {
          satoshis: genesisSatoshis,
          script: newLockingScript,
        },
      ],
    });
    return txnew;
  }

  // make tx issue
  makeTxIssue({ prevTxId, outputIndex, thisOwnerPkh, thisIssuerPkh, thisChangePk, lastTokenId, nextTokenId } = {}) {
    const utxoLockingScript = [this.codePart, this.genesisPart, toHex(thisIssuerPkh) + num2bin(lastTokenId, DataLen8) + ISSUE].join(" ");
    const newLockingScript0 = [this.codePart, this.genesisPart, toHex(thisIssuerPkh) + num2bin(nextTokenId, DataLen8) + ISSUE].join(" ");
    const newLockingScript1 = [this.codePart, this.genesisPart, toHex(thisOwnerPkh) + num2bin(nextTokenId, DataLen8) + TRANSFER].join(" ");

    let txnew = makeTx({
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: 100000000,
          script: utxoLockingScript, // issue
        },
        {
          txid: dummyTxId,
          vout: 0,
          satoshis: 100001000,
          to: dummyPk, // fee
        },
      ],
      outputs: [
        {
          satoshis: 100000000,
          script: newLockingScript0, // issue
        },
        {
          satoshis: 50000000,
          script: newLockingScript1, // transfer
        },
        {
          satoshis: 50000000,
          to: thisChangePk, // change
        },
      ],
    });
    return txnew;
  }

  // make tx transfer
  makeTxTransfer({ prevTxId, outputIndex, lastOwnerPkh, thisOwnerPkh, thisChangePk, lastTokenId, transferTokenId } = {}) {
    const utxoLockingScript = [this.codePart, this.genesisPart, toHex(lastOwnerPkh) + num2bin(lastTokenId, DataLen8) + TRANSFER].join(" ");
    const newLockingScript0 = [this.codePart, this.genesisPart, toHex(thisOwnerPkh) + num2bin(transferTokenId, DataLen8) + TRANSFER].join(" ");
    let txnew = makeTx({
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: 50000000,
          script: utxoLockingScript, // transfer
        },
        {
          txid: dummyTxId,
          vout: 0,
          satoshis: 50001000,
          to: dummyPk, // fee
        },
      ],
      outputs: [
        {
          satoshis: 50000000,
          script: newLockingScript0, // transfer
        },
        {
          satoshis: 50000000,
          to: thisChangePk, // change
        },
      ],
    });
    return txnew;
  }

  // make tx transfer burn
  makeTxTransferBurn({ prevTxId, outputIndex, lastOwnerPkh, thisChangePk, lastTokenId }) {
    const utxoLockingScript = [this.codePart, this.genesisPart, toHex(lastOwnerPkh) + num2bin(lastTokenId, DataLen8) + TRANSFER].join(" ");
    let txnew = makeTx({
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: 50000000,
          script: utxoLockingScript, // transfer
        },
        {
          txid: dummyTxId,
          vout: 0,
          satoshis: 1000,
          to: dummyPk, // fee
        },
      ],
      outputs: [
        {
          satoshis: 50000000,
          to: thisChangePk, // change
        },
      ],
    });
    return txnew;
  }

  ////////////////////////////////////////////////////////////////
  // unlockTxIssue
  async unlockTxIssue({
    txGenesis,
    txIssue,
    newGenisisOutpointTxId,
    newGenesisPreTxHex,
    privKeyIssuer,
    publicKeyIssuer,
    pkhGenesisIssuer,
    receiver1Pkh,
    pkhNewIssuer,
    currTokenId,
  } = {}) {
    // 设置校验环境
    this.token.setDataPart(this.genesisPart + " " + toHex(pkhGenesisIssuer) + num2bin(currTokenId, DataLen8) + ISSUE);
    this.token.txContext = { tx: txIssue, inputIndex, inputSatoshis: 100000000 };

    // 计算preimage
    const preimage = getPreimage(txIssue, this.token.lockingScript.toASM(), 100000000, inputIndex, sighashType);
    // 计算签名
    const sig = signTx(txIssue, privKeyIssuer, this.token.lockingScript.toASM(), 100000000, inputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(newGenisisOutpointTxId, 0, txGenesis.id, newGenesisPreTxHex, txGenesis.serialize());
    const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
    const preTxOutpointMsg = sigInfo.payload;
    const preTxOutpointPadding = sigInfo.padding;

    // 验证
    return this.token.issue(
      new SigHashPreimage(toHex(preimage)),
      preTxOutpointSig,
      new Bytes(preTxOutpointMsg),
      new Bytes(preTxOutpointPadding),
      new Sig(toHex(sig)),
      new PubKey(toHex(publicKeyIssuer)),
      new Ripemd160(toHex(receiver1Pkh)),
      50000000,
      new Ripemd160(toHex(pkhNewIssuer)),
      50000000
    );
  }

  // unlockTxTransfer
  async unlockTxTransfer({ txGenesis, txIssue, txTransfer, newGenisisOutpointTxId, newGenesisPreTxHex, privKeyTransfer, pkhOwner1, pkhOwner2, pkOwner1, currTokenId } = {}) {
    this.token.setDataPart(this.genesisPart + " " + toHex(pkhOwner1) + num2bin(currTokenId + 1, DataLen8) + TRANSFER);
    this.token.txContext = { tx: txTransfer, inputIndex, inputSatoshis: 50000000 };

    // 计算preimage
    const preimage = getPreimage(txTransfer, this.token.lockingScript.toASM(), 50000000, inputIndex, sighashType);

    // 计算签名
    const sig = signTx(txTransfer, privKeyTransfer, this.token.lockingScript.toASM(), 50000000, inputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(txGenesis.id, 0, txIssue.id, txGenesis.serialize(), txIssue.serialize());
    const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
    const preTxOutpointMsg = sigInfo.payload;
    const preTxOutpointPadding = sigInfo.padding;

    return this.token.transfer(
      new SigHashPreimage(toHex(preimage)),
      preTxOutpointSig,
      new Bytes(preTxOutpointMsg),
      new Bytes(preTxOutpointPadding),
      new Sig(toHex(sig)),
      new PubKey(toHex(pkOwner1)),
      new Ripemd160(toHex(pkhOwner2)),
      50000000,
      new Ripemd160(toHex(pkhOwner1)),
      50000000
    );
  }

  //
  async unlockTxTransferBurn({ txTransferBurn, privKeyTransfer, pkhOwner, pkOwner, transferTokenId } = {}) {
    this.token.setDataPart(this.genesisPart + " " + toHex(pkhOwner) + num2bin(transferTokenId, DataLen8) + TRANSFER);
    this.token.txContext = { tx: txTransferBurn, inputIndex, inputSatoshis: 50000000 };

    // 计算preimage
    const preimage = getPreimage(txTransferBurn, this.token.lockingScript.toASM(), 50000000, inputIndex, sighashType);
    // 计算签名
    const sig = signTx(txTransferBurn, privKeyTransfer, this.token.lockingScript.toASM(), 50000000, inputIndex, sighashType);

    return this.token.burn(new SigHashPreimage(toHex(preimage)), new Sig(toHex(sig)), new PubKey(toHex(pkOwner)), new Ripemd160(toHex(pkhOwner)), 50000000);
  }
}

module.exports = {
  NFT,
};
