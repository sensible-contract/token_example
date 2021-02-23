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

const { PayloadNFT } = require("./payload_nft");
const { PayloadToken } = require("./payload_token");
const { privateKey } = require("../privateKey");

const dummyPk = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPk.toBuffer());
const dummyAddress = privateKey.toAddress();

const FEE = 40000;
const issueSatoshis = 5000;
const transferSatoshis = 5000;

const Signature = bsv.crypto.Signature;
const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

const ISSUE = "00";
const TRANSFER = "01";
const SWAP = "02";
const SELL = "03";

/**
 * NFT Tx forge，创建合约相关的Tx，执行对应签名
 */
class NFT {
  /**
   * 创建nft forge, 如果参数deploy为true，则会使用真实utxos创建Tx，否则使用dummy utxos。
   *
   * @param {Boolean} deploy 是否是部署
   * @constructor NFT合约 forge
   */
  constructor(deploy = false) {
    const rabinPubKey = 0x25108ec89eb96b99314619eb5b124f11f00307a833cda48f5ab1865a04d4cfa567095ea4dd47cdf5c7568cd8efa77805197a67943fe965b0a558216011c374aa06a7527b20b0ce9471e399fa752e8c8b72a12527768a9fc7092f1a7057c1a1514b59df4d154df0d5994ff3b386a04d819474efbd99fb10681db58b1bd857f6d5n;
    this.deploy = deploy;

    let nftContractDesc;
    let ftContractDesc;
    const compileBeforeTest = !deploy;
    if (compileBeforeTest) {
      /* 实时编译 */
      nftContractDesc = compileContract("nft.scrypt");
      ftContractDesc = compileContract("token.scrypt");
    } else {
      /* 预编译 */
      nftContractDesc = loadDesc("nft_desc.json");
      ftContractDesc = loadDesc("token_desc.json");
    }
    const nftContractClass = buildContractClass(nftContractDesc);
    const ftContractClass = buildContractClass(ftContractDesc);
    this.nft = new nftContractClass(rabinPubKey);
    this.ft = new ftContractClass(rabinPubKey);
    this.nftCodePart = this.nft.codePart.toASM();
    this.ftCodePart = this.ft.codePart.toASM();

  }

  /**
   * 创建一个新的Tx，用作GenesisTx溯源；发布时不需要这一步，直接用现成的utxo即可
   *
   * @param {Object} params 必要参数
   * @param {number} params.outputSatoshis 输出satoshi
   *
   * @returns {Tx} tx
   */
  makeTxP2pk({ outputSatoshis }) {
    let tx = createDummyPayByOthersTx(dummyTxId);
    let txnew = makeTx({
      tx: tx,
      inputs: [],
      outputs: [
        {
          satoshis: outputSatoshis,
          to: dummyAddress,
        },
      ],
    });
    txnew.change(dummyAddress).fee(FEE);
    return txnew;
  }

  /**
   * 设置溯源outpoint信息
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 溯源txid
   * @param {number} params.outputIndex 溯源outputIndex
   * @param {number=} params.issueOutputIndex = 0 溯源初始发起的Issue输出的outputIdx
   *
   * @returns {Tx} tx
   */
  setTxGenesisPart({ prevTxId, outputIndex, issueOutputIndex = 0 }) {
    this.nftGenesisPart = reverseEndian(prevTxId) + num2bin(outputIndex, DataLen4) + num2bin(issueOutputIndex, DataLen4);
  }


  /**
   * 使用溯源outpoint创建GenesisTx，指定发行人和起始tokenId
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 溯源txid
   * @param {Ripemd160} params.outputIssuerPkh 初始化发行人Pkh
   * @param {number} params.outputTokenId 初始化发行tokenId
   *
   * @returns {Tx} tx
   */
  async makeTxGenesis({ prevTxId, outputIssuerPkh, outputTokenId }) {
    let pl = new PayloadNFT({ dataType: ISSUE, ownerPkh: outputIssuerPkh, tokenId: outputTokenId });
    const newLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    // 创建有基本输入utxo的Tx模板
    let tx = createDummyPayByOthersTx(prevTxId);
    if (this.deploy) {
      // 如果是发布Tx，则需要用真实有余额的地址创建utxo
      tx = await createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [],
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
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个issue utxo txid
   * @param {number} params.outputIndex 上一个issue utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Ripemd160} outs.outputOwnerPkh 新Token接收人Pkh
   * @param {number} outs.outputTokenId 下一个发行tokenId, 应当为inputTokenId+1
   * @param {Ripemd160} outs.changeAddress 找零地址
   * @returns {Tx} tx
   */
  async makeTxIssue({ prevTxId, outputIndex, pl }, { outputOwnerPkh, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    const newLockingScript1 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
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
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Ripemd160} outs.outputOwnerPkh Token新的所属人pkh
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @param {Ripemd160} outs.changeAddress 找零地址
   * @returns {Tx} tx
   */
  async makeTxTransfer({ prevTxId, outputIndex, pl }, { outputOwnerPkh, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
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
   * 创建 SwapTokenTx
   * NFT拥有者标记以某一Token价格交换nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Sha256} outs.codeWithGenesisPartHashSwap 希望Swap的Token溯源
   * @param {number} outs.tokenAmountSwap 希望Swap的Token数量Amount
   * @param {Ripemd160} outs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @param {Ripemd160} outs.changeAddress 找零地址
   *
   * @returns {Tx} tx
   */
  async makeTxSwapToken({ prevTxId, outputIndex, pl }, { codeWithGenesisPartHashSwap, tokenAmountSwap, outputOwnerPkh, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = SWAP;
    pl.codeWithGenesisPartHashSwap = codeWithGenesisPartHashSwap;
    pl.tokenAmountSwap = tokenAmountSwap;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
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
          script: newLockingScript0, // swap
        },
      ],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  /**
   * 创建 CancelSwapTokenTx
   * NFT拥有者取消以某一Token价格交换nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Ripemd160} outs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @param {Ripemd160} outs.changeAddress 找零地址
   *
   * @returns {Tx} tx
   */
  async makeTxCancelSwapToken({ prevTxId, outputIndex, pl }, { outputOwnerPkh, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScript, // swap
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
   * 创建 FinishSwapTokenTx
   * NFT拥有者取消以某一Token价格交换nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevNFTTxId 上一个NFT transfer utxo txid
   * @param {number} params.prevNFToutputIndex 上一个NFT transfer utxo outputIndex
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} side side token参数
   * @param {Sha256} side.prevTokenTxId 上一个Token transfer utxo txid
   * @param {number} side.prevTokenOutputIndex 上一个Token transfer utxo outputIndex
   * @param {number} side.inputTokenAmount 实际Swap的Token数量Amount
   * @param {number} side.tokenGenesisPrevTxId 实际Swap的Token溯源TxId
   * @param {number} side.tokenGenesisOutputIndex 实际Swap的Token溯源outputIndex
   * @param {number} side.tokenGenesisIssueOutputIndex 实际Swap的Token溯源outputIdx
   *
   * @param {Object} outs 输出
   * @param {Sha256} outs.codeWithGenesisPartHashSwap 希望Swap的Token溯源
   * @param {number} outs.tokenAmountSwap 希望Swap的Token数量Amount
   * @param {Ripemd160} outs.inputOwnerPkh Token原来的所属人pkh
   * @param {number} outs.inputTokenId Token原来的Id，输入锁定脚本中的tokenId
   * @param {Ripemd160} outs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   *
   * @returns {Tx} tx
   */
  async makeTxFinishSwapToken(
    { prevNFTTxId, prevNFToutputIndex, changeAddress },
    { prevTokenTxId, prevTokenOutputIndex, inputTokenAmount, tokenGenesisPrevTxId, tokenGenesisOutputIndex, tokenGenesisIssueOutputIndex },
    { codeWithGenesisPartHashSwap, tokenAmountSwap, inputOwnerPkh, inputTokenId, outputOwnerPkh, outputTokenId }
  ) {
    let plNFT = new PayloadNFT({ dataType: SWAP, ownerPkh: inputOwnerPkh, tokenId: inputTokenId });
    plNFT.codeWithGenesisPartHashSwap = codeWithGenesisPartHashSwap;
    plNFT.tokenAmountSwap = tokenAmountSwap;
    const utxoLockingScriptNFT = [this.nftCodePart, this.nftGenesisPart, plNFT.dump()].join(" ");

    plNFT.dataType = TRANSFER;
    plNFT.ownerPkh = outputOwnerPkh;
    plNFT.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, plNFT.dump()].join(" ");

    let tokenGenesisPart =
      reverseEndian(tokenGenesisPrevTxId) + num2bin(tokenGenesisOutputIndex, DataLen4) + num2bin(tokenGenesisIssueOutputIndex, DataLen4);

    let plToken = new PayloadToken({ dataType: TRANSFER, ownerPkh: inputOwnerPkh, tokenAmount: inputTokenAmount });
    const utxoLockingScriptToken = [this.ftCodePart, tokenGenesisPart, plToken.dump()].join(" ");

    plToken.ownerPkh = outputOwnerPkh;
    const newLockingScript1 = [this.ftCodePart, tokenGenesisPart, plToken.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevNFTTxId,
          vout: prevNFToutputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScriptNFT, // nft swap
        },
        {
          txid: prevTokenTxId,
          vout: prevTokenOutputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScriptToken, // token transfer
        },
      ],
      outputs: [
        {
          satoshis: transferSatoshis,
          script: newLockingScript0, // nft transfer
        },
        {
          satoshis: transferSatoshis,
          script: newLockingScript1, // token transfer
        },
      ],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  /**
   * 创建 SellTx
   * NFT拥有者标记以一定bsv价格出售nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {number} outs.satoshiAmountSell 出售价格
   * @param {Ripemd160} outs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @param {Ripemd160} outs.changeAddress 找零地址
   *
   * @returns {Tx} tx
   */
  async makeTxSell({ prevTxId, outputIndex, pl }, { satoshiAmountSell, outputOwnerPkh, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = SELL;
    pl.satoshiAmountSell = satoshiAmountSell;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
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
          script: newLockingScript0, // sell
        },
      ],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  /**
   * 创建 CancelSellTx
   * NFT拥有者取消出售nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个selling utxo txid
   * @param {number} params.outputIndex 上一个selling utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Ripemd160} outs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @param {Ripemd160} outs.changeAddress 找零地址
   *
   * @returns {Tx} tx
   */
  async makeTxCancelSell({ prevTxId, outputIndex, pl }, { outputOwnerPkh, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScript, // sell
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
   * 创建 BuyTx
   * 购买者使用Bsv兑换NFT拥有者出售的nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个selling utxo txid
   * @param {number} params.outputIndex 上一个selling utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Ripemd160} outs.outputOwnerPkh Token输出给购买者pkh
   * @param {number} outs.buyerSatoshis Token输出给购买者的bsv
   * @param {Ripemd160} outs.inputOwnerPkh Token原来的所属人pkh
   * @param {number} outs.satoshiAmountSell 出售价格
   * @param {number} outs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @param {Ripemd160} outs.changeAddress 找零地址
   *
   * @returns {Tx} tx
   */
  async makeTxBuy({ prevTxId, outputIndex, pl }, { outputOwnerPkh, buyerSatoshis, inputOwnerPkh, satoshiAmountSell, outputTokenId, changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
    }
    let txnew = makeTx({
      tx: tx,
      inputs: [
        {
          txid: prevTxId,
          vout: outputIndex,
          satoshis: transferSatoshis,
          script: utxoLockingScript, // sell
        },
      ],
      outputs: [
        {
          satoshis: buyerSatoshis,
          script: newLockingScript0, // transfer buyer
        },
        {
          satoshis: satoshiAmountSell + transferSatoshis,
          to: bsv.Address(inputOwnerPkh),
        },
      ],
    });
    txnew.change(changeAddress).fee(FEE);
    return txnew;
  }

  /**
   * 创建 TransferBurnTx
   * 用户自行销毁nft，并取回nft上的bsv
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {PayloadNFT} params.pl 输入锁定
   *
   * @param {Object} outs 输出
   * @param {Ripemd160} outs.changeAddress 找零地址
   *
   * @returns {Tx} tx
   */
  async makeTxTransferBurn({ prevTxId, outputIndex, pl }, { changeAddress }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    let tx = createDummyPayByOthersTx(dummyTxId);
    if (this.deploy) {
      tx = await createPayByOthersTx(dummyAddress);
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
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxIssue创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Ripemd160} params.outputOwnerPkh 接收人pkh
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyIssuer 发行者私钥
   * @param {Pubkey} envs.publicKeyIssuer 发行者公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */
  async unlockTxIssue({ tx, pl, outputOwnerPkh, changePkh }, { privKeyIssuer, publicKeyIssuer }, satotxData) {
    // 设置校验环境
    const changeAmount = tx.inputAmount - FEE - issueSatoshis - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: issueSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);
    // 计算签名
    const sig = signTx(tx, privKeyIssuer, this.nft.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.issue(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

      new Sig(toHex(sig)),
      new PubKey(toHex(publicKeyIssuer)),
      new Ripemd160(toHex(outputOwnerPkh)),
      transferSatoshis,
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
        // console.log("sig:", i, tx.inputs[i].script.toASM())
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
      // console.log("sig:", curInputIndex, unlockingScript.toASM())
    }

    // 验证
    return contractObj;
  }

  /**
   * unlockTxTransfer
   * 为之前创建的Transfer Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxTransfer创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Ripemd160} params.outputOwnerPkh 新所属人的公钥Hash
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */
  async unlockTxTransfer({ tx, pl, outputOwnerPkh, changePkh }, { privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.transfer(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

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
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }

  /**
   * 为之前创建的TransferBurn Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxTransferBurn创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @returns {Object} Contract
   */
  async unlockTxTransferBurn({ tx, pl, changePkh }, { privKeyTransfer, inputOwnerPk }) {
    const changeAmount = tx.inputAmount - FEE;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);
    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    return this.nft.burn(
      new SigHashPreimage(toHex(preimage)),
      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );
  }

  /**
   * unlockTxSwapToken
   * 为之前创建的SwapToken Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxSwapToken创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Sha256} params.codeWithGenesisPartHashSwap 希望Swap的Token溯源
   * @param {number} params.tokenAmountSwap 希望Swap的Token数量Amount
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxSwapToken({ tx, pl, codeWithGenesisPartHashSwap, tokenAmountSwap, changePkh }, { privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.makeSwapToken(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),

      new Sha256(toHex(codeWithGenesisPartHashSwap)),
      tokenAmountSwap,
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }

  /**
   * unlockTxCancelSwapToken
   * 为之前创建的CancelSwapToken Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxCancelSwapToken创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxCancelSwapToken({ tx, pl, changePkh }, { privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.cancelSwapToken(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),

      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }

  /**
   * unlockTxSell
   * 为之前创建的Sell Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxSell创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {number} params.satoshiAmountSell 出售价格
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxSell({ tx, pl, satoshiAmountSell, changePkh }, { privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.sell(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),

      satoshiAmountSell,
      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }

  /**
   * unlockTxCancelSell
   * 为之前创建的CancelSell Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxCancelSell创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxCancelSell({ tx, pl, changePkh }, { privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.cancelSell(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

      new Sig(toHex(sig)),
      new PubKey(toHex(inputOwnerPk)),

      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }

  /**
   * unlockTxBuy
   * 为之前创建的Buy Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxBuy创建的Tx对象
   * @param {PayloadNFT} params.pl 输入锁定
   * @param {Ripemd160} params.outputOwnerPkh 购买人地址
   * @param {number} params.buyerSatoshis 购买存入bsv
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxBuy({ tx, pl, outputOwnerPkh, buyerSatoshis, changePkh }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - buyerSatoshis - pl.satoshiAmountSell - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nft.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nft.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nft.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nft.buy(
      new SigHashPreimage(toHex(preimage)),
      BigInt("0x" + sigInfo.sigBE),
      new Bytes(sigInfo.payload),
      new Bytes(sigInfo.padding),

      new Ripemd160(toHex(outputOwnerPkh)),
      buyerSatoshis,

      new Ripemd160(toHex(changePkh)),
      changeAmount
    );

    if (this.deploy) {
      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
    }

    return contractObj;
  }
}

module.exports = {
  NFT,
};
