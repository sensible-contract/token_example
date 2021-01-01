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
 * NFT Tx forge，创建合约相关的Tx，执行对应签名
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
    const rabinPubKey = 0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn;
    this.deploy = deploy;

    const compileBeforeTest = true;
    if (compileBeforeTest) {
      /* 实时编译 */
      const NonFungibleTokenContractClass = buildContractClass(compileContract("nft.scrypt"));
      this.nonFungibleToken = new NonFungibleTokenContractClass(rabinPubKey);

      const FungibleTokenContractClass = buildContractClass(compileContract("token.scrypt"));
      this.fungibleToken = new FungibleTokenContractClass(rabinPubKey);
    } else {
      /* 预编译 */
      const NonFungibleTokenContractClass = buildContractClass(loadDesc("nft_desc.json"));
      this.nonFungibleToken = new NonFungibleTokenContractClass(rabinPubKey);

      const FungibleTokenContractClass = buildContractClass(loadDesc("token_desc.json"));
      this.fungibleToken = new FungibleTokenContractClass(rabinPubKey);
    }
    this.nftCodePart = this.nonFungibleToken.codePart.toASM();
    this.tokenCodePart = this.fungibleToken.codePart.toASM();
  }

  /**
   *
   * 创建一个新的Tx，用作GenesisTx溯源；发布时不需要这一步，直接用现成的utxo即可
   *
   * @param {Object} params 必要参数
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
          satoshis: outputSatoshis,
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
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 溯源txid
   * @param {number} params.outputIndex 溯源outputIndex
   * @param {number=} params.issueOutputIndex = 0 溯源初始发起的Issue输出的outputIdx
   * @param {Ripemd160} params.outputIssuerPkh 初始化发行人Pkh
   * @param {number} params.outputTokenId 初始化发行tokenId
   *
   * @returns {Tx} tx
   */
  makeTxGenesis({ prevTxId, outputIndex, issueOutputIndex = 0, outputIssuerPkh, outputTokenId }) {
    this.nftGenesisPart = reverseEndian(prevTxId) + num2bin(outputIndex, DataLen4) + num2bin(issueOutputIndex, DataLen4);

    let pl = new PayloadNFT({ dataType: ISSUE, ownerPkh: outputIssuerPkh, tokenId: outputTokenId });
    const newLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个issue utxo txid
   * @param {number} params.outputIndex 上一个issue utxo outputIndex
   * @param {Ripemd160} params.outputOwnerPkh 新Token接收人Pkh
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {number} envs.outputTokenId 下一个发行tokenId, 应当为inputTokenId+1
   * @returns {Tx} tx
   */
  makeTxIssue({ prevTxId, outputIndex, outputOwnerPkh, changeAddress }, { pl, outputTokenId }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    const newLockingScript1 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {Ripemd160} params.outputOwnerPkh Token新的所属人pkh
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxTransfer({ prevTxId, outputIndex, outputOwnerPkh, changeAddress }, { pl, outputTokenId }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * 创建 SwapTokenTx
   * NFT拥有者标记以某一Token价格交换nft
   *
   * @param {Object} params 必要参数
   * @param {Sha256} params.prevTxId 上一个transfer utxo txid
   * @param {number} params.outputIndex 上一个transfer utxo outputIndex
   * @param {Sha256} params.codeWithGenesisPartHashSwap 希望Swap的Token溯源
   * @param {number} params.tokenAmountSwap 希望Swap的Token数量Amount
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {Ripemd160} envs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxSwapToken({ prevTxId, outputIndex, codeWithGenesisPartHashSwap, tokenAmountSwap, changeAddress }, { pl, outputOwnerPkh, outputTokenId }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = SWAP;
    pl.codeWithGenesisPartHashSwap = codeWithGenesisPartHashSwap;
    pl.tokenAmountSwap = tokenAmountSwap;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {Ripemd160} envs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxCancelSwapToken(
    { prevTxId, outputIndex, changeAddress },
    { pl, outputOwnerPkh, outputTokenId }
  ) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Object} envs 调用环境
   * @param {Sha256} envs.codeWithGenesisPartHashSwap 希望Swap的Token溯源
   * @param {number} envs.tokenAmountSwap 希望Swap的Token数量Amount
   * @param {Ripemd160} envs.inputOwnerPkh Token原来的所属人pkh
   * @param {number} envs.inputTokenId Token原来的Id，输入锁定脚本中的tokenId
   * @param {Ripemd160} envs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxFinishSwapToken(
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
    const utxoLockingScriptToken = [this.tokenCodePart, tokenGenesisPart, plToken.dump()].join(" ");

    plToken.ownerPkh = outputOwnerPkh;
    const newLockingScript1 = [this.tokenCodePart, tokenGenesisPart, plToken.dump()].join(" ");

    let tx = createDummyPayByOthersTx();
    if (this.deploy) {
      tx = createPayByOthersTx(dummyAddress);
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
   * @param {number} params.satoshiAmountSell 出售价格
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {Ripemd160} envs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxSell({ prevTxId, outputIndex, satoshiAmountSell, changeAddress }, { pl, outputOwnerPkh, outputTokenId }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = SELL;
    pl.satoshiAmountSell = satoshiAmountSell;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {number} envs.satoshiAmountSell 出售价格
   * @param {Ripemd160} envs.outputOwnerPkh Token输出的所属人pkh，应当和原所属人一致
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxCancelSell({ prevTxId, outputIndex, changeAddress }, { pl, satoshiAmountSell, outputOwnerPkh, outputTokenId }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Ripemd160} params.outputOwnerPkh Token输出给购买者pkh
   * @param {number} params.buyerSatoshis Token输出给购买者的bsv
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {Ripemd160} envs.inputOwnerPkh Token原来的所属人pkh
   * @param {number} envs.satoshiAmountSell 出售价格
   * @param {number} envs.outputTokenId Token新的Id，输出锁定脚本中的tokenId, 应当和原Id保持一致
   * @returns {Tx} tx
   */
  makeTxBuy({ prevTxId, outputIndex, outputOwnerPkh, buyerSatoshis, changeAddress }, { pl, inputOwnerPkh, satoshiAmountSell, outputTokenId }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

    pl.dataType = TRANSFER;
    pl.ownerPkh = outputOwnerPkh;
    pl.tokenId = outputTokenId;
    const newLockingScript0 = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @param {Ripemd160} params.changeAddress 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @returns {Tx} tx
   */
  makeTxTransferBurn({ prevTxId, outputIndex, changeAddress }, { pl }) {
    const utxoLockingScript = [this.nftCodePart, this.nftGenesisPart, pl.dump()].join(" ");

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
   * @typedef {Object} IssueEnvs 调用环境
   * @property {PayloadNFT} pl
   * @property {PrivateKey} privKeyIssuer 发行者私钥
   * @property {Pubkey} publicKeyIssuer 发行者公钥
   * @property {Ripemd160} inputIssuerPkh 必须是输入锁定脚本中的发行者公钥Hash
   * @property {number} inputTokenId 必须是输入锁定脚本中的tokenId
   */

  /**
   * unlockTxIssue
   * 为之前创建的issue Tx生成解锁脚本，并签名其他输入
   *
   * @param {Object} params 必要参数
   * @param {Tx} params.tx 用makeTxIssue创建的Tx对象
   * @param {Ripemd160} params.outputOwnerPkh 接收人pkh
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {PrivateKey} envs.privKeyIssuer 发行者私钥
   * @param {Pubkey} envs.publicKeyIssuer 发行者公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */
  async unlockTxIssue({ tx, outputOwnerPkh, changePkh }, { pl, privKeyIssuer, publicKeyIssuer }, satotxData) {
    // 设置校验环境
    const changeAmount = tx.inputAmount - FEE - issueSatoshis - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nonFungibleToken.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nonFungibleToken.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: issueSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nonFungibleToken.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);
    // 计算签名
    const sig = signTx(tx, privKeyIssuer, this.nonFungibleToken.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nonFungibleToken.issue(
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
      }
      const unlockingScript = contractObj.toScript();
      tx.inputs[curInputIndex].setScript(unlockingScript);
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
   * @param {Ripemd160} params.outputOwnerPkh 新所属人的公钥Hash
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */
  async unlockTxTransfer({ tx, outputOwnerPkh, changePkh }, { pl, privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nonFungibleToken.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nonFungibleToken.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nonFungibleToken.transfer(
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
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @returns {Object} Contract
   */
  async unlockTxTransferBurn({ tx, changePkh }, { pl, privKeyTransfer, inputOwnerPk }) {
    const changeAmount = tx.inputAmount - FEE;
    const curInputIndex = tx.inputs.length - 1;

    this.nonFungibleToken.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nonFungibleToken.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);
    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    return this.nonFungibleToken.burn(
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
   * @param {Sha256} params.codeWithGenesisPartHashSwap 希望Swap的Token溯源
   * @param {number} params.tokenAmountSwap 希望Swap的Token数量Amount
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxSwapToken({ tx, codeWithGenesisPartHashSwap, tokenAmountSwap, changePkh }, { pl, privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nonFungibleToken.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nonFungibleToken.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nonFungibleToken.makeSwapToken(
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
   * @param {Ripemd160} params.changePkh 找零地址
   *
   * @param {Object} envs 调用环境
   * @param {PayloadNFT} envs.pl
   * @param {PrivateKey} envs.privKeyTransfer 之前所属人的私钥
   * @param {PubKey} envs.inputOwnerPk 之前所属人的公钥
   *
   * @param {Object} satotxData
   *
   * @returns {Object} Contract
   */

  async unlockTxCancelSwapToken({ tx, changePkh }, { pl, privKeyTransfer, inputOwnerPk }, satotxData) {
    const changeAmount = tx.inputAmount - FEE - transferSatoshis;
    const curInputIndex = tx.inputs.length - 1;

    this.nonFungibleToken.setDataPart(this.nftGenesisPart + " " + pl.dump());
    this.nonFungibleToken.txContext = { tx: tx, inputIndex: curInputIndex, inputSatoshis: transferSatoshis };

    // 计算preimage
    const preimage = getPreimage(tx, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 计算签名
    const sig = signTx(tx, privKeyTransfer, this.nonFungibleToken.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

    // 获取Oracle签名
    let sigInfo = await satoTxSigUTXOSpendBy(satotxData);

    // 创建解锁
    let contractObj = this.nonFungibleToken.cancelSwapToken(
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
}

module.exports = {
  NFT,
};
