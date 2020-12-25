const { bsv, buildContractClass, signTx, toHex, getPreimage, num2bin, Ripemd160, PubKey, SigHashPreimage, Sig, Bytes } = require("scryptlib");
const {
  inputIndex,
  compileContract,
  loadDesc,
  DataLen,
  DataLen4,
  DataLen8,
  dummyTxId,
  satoTxSigUTXOSpendBy,
  satoTxSigUTXO,
  reverseEndian,
  createDummyPayByOthersTx,
  makeTx,
  createPayByOthersTx,
  unlockP2PKHInput,
} = require("../helper");

const { privateKey } = require("../privateKey");

const dummyPk = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPk.toBuffer());
const dummyAddress = privateKey.toAddress();

const FEE = 10000;
const issueSatoshis = 5000;
const transferSatoshis = 5000;

const Signature = bsv.crypto.Signature;
// Note: ANYONECANPAY
const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

const ISSUE = "00";
const TRANSFER = "01";
const SWAP = "02";
const SELL = "03";

//////////////// PayloadNFT
class PayloadNFT {
  constructor({ scriptCode, dataType, ownerPkh, tokenId, codeWithGenesisPartHashSwap, amountSwap, satoshiAmountSell } = {}) {
    /* 数据类型，1字节 */
    this.dataType = dataType;

    /* 数据 */
    this.ownerPkh = ownerPkh; // Ripemd160
    this.tokenId = tokenId;

    /* swap 数据 */
    this.codeWithGenesisPartHashSwap = codeWithGenesisPartHashSwap; // Sha256
    this.amountSwap = amountSwap;

    /* sell 数据 */
    this.satoshiAmountSell = satoshiAmountSell; // int
  }

  dump() {
    let payload = "";
    if (this.dataType == SWAP) {
      payload =
        toHex(this.ownerPkh) +
        num2bin(this.tokenId, DataLen8) +
        this.codeWithGenesisPartHashSwap +
        num2bin(this.amountSwap, DataLen8) +
        this.dataType;
    } else if (this.dataType == SELL) {
      payload = toHex(this.ownerPkh) + num2bin(this.tokenId, DataLen8) + num2bin(this.satoshiAmountSell, DataLen8) + this.dataType;
    } else {
      payload = toHex(this.ownerPkh) + num2bin(this.tokenId, DataLen8) + this.dataType;
    }
    return payload;
  }
}

//////////////// rabin pubkey
const rabinPubKey = 0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn;

//////////////// NFT
class NFT {
  constructor(deploy = false) {
    this.deploy = deploy;
    if (true) {
      const TokenContractClass = buildContractClass(loadDesc("nft_desc.json"));
      this.token = new TokenContractClass(rabinPubKey);
    } else {
      const TokenContractClass = buildContractClass(compileContract("nft.scrypt"));
      this.token = new TokenContractClass(rabinPubKey);
    }
    this.codePart = this.token.codePart.toASM();
  }

  // prevTx of GenesisTx
  makeTxP2pk({ outputSatoshis } = {}) {
    let tx = createDummyPayByOthersTx();
    let txnew = makeTx({
      tx: tx,
      inputs: [],
      outputs: [
        {
          satoshis: issueSatoshis,
          to: dummyAddress,
        },
      ],
    });
    txnew.change(dummyAddress).fee(FEE);
    return txnew;
  }

  // GenesisTx
  makeTxGenesis({ prevTxId, outputIndex, outputIssuerPkh, outputTokenId } = {}) {
    this.genesisPart = reverseEndian(prevTxId) + num2bin(outputIndex, DataLen4) + num2bin(0, DataLen4);

    let pl = new PayloadNFT({ dataType: ISSUE, ownerPkh: outputIssuerPkh, tokenId: outputTokenId });
    const newLockingScript = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx();
    if (this.deploy) {
      tx = createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId, // genesis utxo
          vout: outputIndex,
          satoshis: issueSatoshis,
          to: dummyAddress,
        },
      ],
      outputs: [
        {
          satoshis: issueSatoshis,
          script: newLockingScript,
        },
      ],
    });
    txnew.change(dummyAddress).fee(FEE);
    return txnew;
  }

  // make tx issue
  makeTxIssue({ prevTxId, outputIndex, inputIssuerPkh, outputOwnerPkh, changeAddress, inputTokenId, outputTokenId } = {}) {
    let pl = new PayloadNFT({ dataType: ISSUE, ownerPkh: inputIssuerPkh, tokenId: inputTokenId });
    const utxoLockingScript = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    const newLockingScript1 = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx();
    if (this.deploy) {
      tx = createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: issueSatoshis,
          script: utxoLockingScript, // issue
        },
      ],
      outputs: [
        {
          satoshis: issueSatoshis,
          script: newLockingScript0, // issue
        },
        {
          satoshis: transferSatoshis,
          script: newLockingScript1, // transfer
        },
      ],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  // make tx transfer
  makeTxTransfer({ prevTxId, outputIndex, inputOwnerPkh, outputOwnerPkh, changeAddress, inputTokenId, outputTokenId } = {}) {
    let pl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: inputOwnerPkh, tokenId: inputTokenId });
    const utxoLockingScript = [this.codePart, this.genesisPart, pl.dump()].join(" ");
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx();
    if (this.deploy) {
      tx = createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScript, // transfer
        },
      ],
      outputs: [
        {
          satoshis: transferSatoshis,
          script: newLockingScript0, // transfer
        },
      ],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  // make tx transfer burn
  makeTxTransferBurn({ prevTxId, outputIndex, inputOwnerPkh, changeAddress, inputTokenId }) {
    let pl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: inputOwnerPkh, tokenId: inputTokenId });
    const utxoLockingScript = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx();
    if (this.deploy) {
      tx = createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScript, // transfer
        },
      ],
      outputs: [],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  ////////////////////////////////////////////////////////////////
  // unlockTxIssue
  async unlockTxIssue({
    txIssue,
    preTxId,
    preTxHex,
    preUtxoTxId,
    preUtxoOutputIndex,
    preUtxoTxHex,
    privKeyIssuer,
    publicKeyIssuer,
    inputIssuerPkh,
    outputReceiverPkh,
    changePkh,
    inputTokenId,
  } = {}) {
    // 设置校验环境

    // console.log("unlock tx:", txIssue.serialize());
    const changeAmount = txIssue.inputAmount - FEE - issueSatoshis - transferSatoshis;
    const curInputIndex = txIssue.inputs.length - 1;

    let pl = new PayloadNFT({ dataType: ISSUE, ownerPkh: inputIssuerPkh, tokenId: inputTokenId });
    this.token.setDataPart(this.genesisPart + " " + pl.dump());
    this.token.txContext = { tx: txIssue, inputIndex: curInputIndex, inputSatoshis: issueSatoshis };

    // 计算preimage
    const preimage = getPreimage(txIssue, this.token.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);
    // 计算签名
    const sig = signTx(txIssue, privKeyIssuer, this.token.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(preUtxoTxId, preUtxoOutputIndex, preTxId, preUtxoTxHex, preTxHex);
    const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
    const preTxOutpointMsg = sigInfo.payload;
    const preTxOutpointPadding = sigInfo.padding;

    let contractObj = this.token.issue(
      new SigHashPreimage(toHex(preimage)),
      preTxOutpointSig,
      new Bytes(preTxOutpointMsg),
      new Bytes(preTxOutpointPadding),
      new Sig(toHex(sig)),
      new PubKey(toHex(publicKeyIssuer)),
      new Ripemd160(toHex(outputReceiverPkh)),
      transferSatoshis,
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, txIssue, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      txIssue.inputs[curInputIndex].setScript(unlockingScript);
    }

    // 验证
    return contractObj;
  }

  // unlockTxTransfer
  async unlockTxTransfer({
    txTransfer,
    preTxId,
    preTxHex,
    preUtxoTxId,
    preUtxoOutputIndex,
    preUtxoTxHex,
    privKeyTransfer,
    inputOwnerPkh,
    outputOwnerPkh,
    inputOwnerPk,
    changePkh,
    inputTokenId,
  } = {}) {
    const changeAmount = txTransfer.inputAmount - FEE - transferSatoshis;
    const curInputIndex = txTransfer.inputs.length - 1;

    let pl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: inputOwnerPkh, tokenId: inputTokenId });
    this.token.setDataPart(this.genesisPart + " " + pl.dump());
    this.token.txContext = { tx: txTransfer, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(txTransfer, this.token.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(txTransfer, privKeyTransfer, this.token.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(preUtxoTxId, preUtxoOutputIndex, preTxId, preUtxoTxHex, preTxHex);
    const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
    const preTxOutpointMsg = sigInfo.payload;
    const preTxOutpointPadding = sigInfo.padding;

    let contractObj = this.token.transfer(
      new SigHashPreimage(toHex(preimage)),
      preTxOutpointSig,
      new Bytes(preTxOutpointMsg),
      new Bytes(preTxOutpointPadding),
      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),
      new Ripemd160(toHex(outputOwnerPkh)),
      transferSatoshis,
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, txTransfer, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      txTransfer.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }

  //
  async unlockTxTransferBurn({ txTransferBurn, privKeyTransfer, inputOwnerPkh, inputOwnerPk, changePkh, inputTokenId } = {}) {
    const changeAmount = txTransferBurn.inputAmount - FEE;
    const curInputIndex = txTransferBurn.inputs.length - 1;

    let pl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: inputOwnerPkh, tokenId: inputTokenId });
    this.token.setDataPart(this.genesisPart + " " + pl.dump());
    this.token.txContext = { tx: txTransferBurn, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(txTransferBurn, this.token.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);
    // 计算签名
    const sig = signTx(txTransferBurn, privKeyTransfer, this.token.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    return this.token.burn(
      new SigHashPreimage(toHex(preimage)),
      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );
  }
}

module.exports = {
  NFT,
};
