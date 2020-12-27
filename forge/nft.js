const { bsv, buildContractClass, signTx, toHex, getPreimage, num2bin, Ripemd160, Sha256, PubKey, SigHashPreimage, Sig, Bytes } = require("scryptlib");
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
const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

const ISSUE = "00";
const TRANSFER = "01";
const SWAP = "02";
const SELL = "03";

/**
 * @class PayloadNFT
 * @constructor
 */
class PayloadNFT {
  constructor({ scriptCode, dataType, ownerPkh, tokenId, codeWithGenesisPartHashSwap, amountSwap, satoshiAmountSell }) {
    /* 数据类型，1字节 */
    this.dataType = dataType;

    /* 数据 */
    this.ownerPkh = ownerPkh; // Ripemd160
    this.tokenId = tokenId;

    /* swap 数据 */
    this.codeWithGenesisPartHashSwap = codeWithGenesisPartHashSwap; // Sha256
    this.amountSwap = amountSwap;

    /* sell 数据 */
    this.satoshiAmountSell = satoshiAmountSell; // number
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

/**
 * rabin pubkey
 */
const rabinPubKey = 0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn;

/**
 * NFT Tx forge，创建并签名合约相关的Tx
 */
class NFT {
  /**
   * 创建nft forge, 如果参数deploy为true，则会使用真实utxos创建Tx，否则使用dummy utxos。
   *
   * @param {Boolean} deploy 是否是部署
   *
   * @constructor NFT合约 forge
   */
  constructor(deploy = false) {
    this.deploy = deploy;
    if (false) {
      const TokenContractClass = buildContractClass(loadDesc("nft_desc.json"));
      this.token = new TokenContractClass(rabinPubKey);
    } else {
      const TokenContractClass = buildContractClass(compileContract("nft.scrypt"));
      this.token = new TokenContractClass(rabinPubKey);
    }
    this.codePart = this.token.codePart.toASM();
  }

  /**
   *
   * 创建一个新的Tx，用作GenesisTx溯源；发布时不需要这一步，直接用现成的utxo即可
   *
   * @param {Object} params
   * @param {number} params.outputSatoshis 输出satoshi
   *
   * @returns {Tx} tx
   */
  makeTxP2pk({ outputSatoshis }) {
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

  /**
   * 使用溯源outpoint创建GenesisTx，指定发行人和起始tokenId
   *
   * @param {Object} params
   * @param {Sha256} params.prevTxId 溯源txid
   * @param {number} params.outputIndex 溯源outputIndex
   * @param {number=} params.issueOutputIndex = 0 溯源初始发起的Issue输出的outputIdx
   * @param {Ripemd160} params.outputIssuerPkh 初始化发行人Pkh
   * @param {number} params.outputTokenId 初始化发行tokenId
   *
   * @returns {Tx} tx
   */
  makeTxGenesis({ prevTxId, outputIndex, issueOutputIndex = 0, outputIssuerPkh, outputTokenId }) {
    this.genesisPart = reverseEndian(prevTxId) + num2bin(outputIndex, DataLen4) + num2bin(issueOutputIndex, DataLen4);

    let pl = new PayloadNFT({ dataType: ISSUE, ownerPkh: outputIssuerPkh, tokenId: outputTokenId });
    const newLockingScript = [this.codePart, this.genesisPart, pl.dump()].join(" ");

    // 创建有基本输入utxo的Tx模板
    let tx = createDummyPayByOthersTx();
    if (this.deploy) {
      // 如果是发布Tx，则需要用真实有余额的地址创建utxo
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

  /**
   * 创建IssueTx，发行下一个Token给某接收人
   *
   * @param {Object} params
   * @param {Sha256} params.prevTxId 上一个issue utxo txid
   * @param {number} params.outputIndex 上一个issue utxo outputIndex
   * @param {Ripemd160} params.inputIssuerPkh 发行人Pkh
   * @param {Ripemd160} params.outputOwnerPkh 新Token接收人Pkh
   * @param {Ripemd160} params.changeAddress 找零地址
   * @param {number} params.inputTokenId 输入tokenId
   * @param {number} params.outputTokenId 下一个发行tokenId, 应当为inputTokenId+1
   *
   * @returns {Tx} tx
   */
  makeTxIssue({ prevTxId, outputIndex, inputIssuerPkh, outputOwnerPkh, changeAddress, inputTokenId, outputTokenId }) {
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

  /**
   * 创建 TransferTx
   * Token拥有者转移token到下一个接收人
   *
   * @param {Object} params
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {Ripemd160} params.inputOwnerPkh Token原来的所属人pkh
   * @param {Ripemd160} params.outputOwnerPkh Token新的所属人pkh
   * @param {Ripemd160} params.changeAddress 找零地址
   * @param {number} params.inputTokenId Token原来的Id，输入锁定脚本中的tokenId
   * @param {number} params.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   *
   * @returns {Tx} tx
   */
  makeTxTransfer({ prevTxId, outputIndex, inputOwnerPkh, outputOwnerPkh, changeAddress, inputTokenId, outputTokenId }) {
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

  /**
   * 创建 TransferBurnTx
   * 用户自行销毁token，并取回token上的bsv
   *
   * @param {Object} params
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {Ripemd160} params.inputOwnerPkh Token原来的所属人pkh
   * @param {Ripemd160} params.changeAddress 找零地址
   * @param {number} params.inputTokenId Token原来的Id
   *
   * @returns {Tx} tx
   */
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

  /**
   * unlockTxIssue
   * 为之前创建的issue Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params
   * @param {Tx} params.txIssue 用makeTxIssue创建的Tx对象
   * @param {PrivateKey} params.privKeyIssuer 发行者私钥
   * @param {Pubkey} params.publicKeyIssuer 发行者公钥
   * @param {Ripemd160} params.inputIssuerPkh 发行者公钥Hash
   * @param {Ripemd160} params.outputReceiverPkh 接收人pkh
   * @param {Ripemd160} params.changePkh 找零地址
   * @param {number} params.inputTokenId 输入锁定脚本中的tokenId
   *
   * @param {Object} sigtx
   * @param {Sha256} sigtx.preTxId txIssue前一个txid
   * @param {String} sigtx.preTxHex txIssue前一个tx hex
   * @param {Sha256} sigtx.prevPrevTxId txIssue前前一个txid
   * @param {number} sigtx.prevPrevOutputIndex txIssue前前一个vout
   * @param {String} sigtx.prevPrevTxHex txIssue前前一个tx hex
   *
   * @returns {Object} Contract
   */
  async unlockTxIssue({
    txIssue,
    privKeyIssuer,
    publicKeyIssuer,
    inputIssuerPkh,
    outputReceiverPkh,
    changePkh,
    inputTokenId,
  }, {
    preTxId,
    preTxHex,
    prevPrevTxId,
    prevPrevOutputIndex,
    prevPrevTxHex,
  }) {
    // 设置校验环境
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
    let sigInfo = await satoTxSigUTXOSpendBy(prevPrevTxId, prevPrevOutputIndex, preTxId, prevPrevTxHex, preTxHex);
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

  /**
   * unlockTxTransfer
   * 为之前创建的Transfer Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params
   * @param {Tx} params.txTransfer 用makeTxTransfer创建的Tx对象
   * @param {PrivateKey} params.privKeyTransfer 之前所属人的私钥
   * @param {Ripemd160} params.inputOwnerPkh 之前所属人的公钥Hash
   * @param {Ripemd160} params.outputOwnerPkh 新所属人的公钥Hash
   * @param {PubKey} params.inputOwnerPk 之前所属人的公钥
   * @param {Ripemd160} params.changePkh 找零地址
   * @param {number} params.inputTokenId 输入锁定脚本中的tokenId
   *
   * @param {Object} sigtx
   * @param {Sha256} sigtx.preTxId txTransfer前一个txid
   * @param {String} sigtx.preTxHex txTransfer前一个tx hex
   * @param {Sha256} sigtx.prevPrevTxId txTransfer前前一个txid
   * @param {number} sigtx.prevPrevOutputIndex txTransfer前前一个vout
   * @param {String} sigtx.prevPrevTxHex txTransfer前前一个tx hex
   * @returns {Object} Contract
   */
  async unlockTxTransfer({
    txTransfer,
    privKeyTransfer,
    inputOwnerPkh,
    outputOwnerPkh,
    inputOwnerPk,
    changePkh,
    inputTokenId,
  },{
    preTxId,
    preTxHex,
    prevPrevTxId,
    prevPrevOutputIndex,
    prevPrevTxHex,
  }) {
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
    let sigInfo = await satoTxSigUTXOSpendBy(prevPrevTxId, prevPrevOutputIndex, preTxId, prevPrevTxHex, preTxHex);
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

  /**
   * 为之前创建的TransferBurn Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params
   * @param {Sha256} params.txTransferBurn 用makeTxTransferBurn创建的Tx对象
   * @param {PrivateKey} params.privKeyTransfer 之前所属人的私钥
   * @param {Ripemd160} params.inputOwnerPkh 之前所属人的公钥Hash
   * @param {PubKey} params.inputOwnerPk 之前所属人的公钥
   * @param {Ripemd160} params.changePkh 找零地址
   * @param {number} params.inputTokenId 输入锁定脚本中的tokenId
   *
   * @returns {Object} Contract
   */
  async unlockTxTransferBurn({ txTransferBurn, privKeyTransfer, inputOwnerPkh, inputOwnerPk, changePkh, inputTokenId }) {
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
