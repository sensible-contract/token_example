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


const MINT = "00";
const TRANSFER = "01";
const SWAP = "02";
const SELL = "03";

/**
 * PayloadToken
 */
class PayloadToken {
  /**
   * 解析、构造Token合约的数据部分
   *
   * @constructor
   *
   * @param {Object} params
   * @param {String=} params.scriptCode 合约代码部分
   * @param {string} params.dataType 数据类型，1字节
   * @param {Ripemd160} params.ownerPkh 所属人
   * @param {number} params.tokenAmount tokenAmount
   *
   * mint
   * @param {String=} params.blockHeader 区块头字节
   * @param {number=} params.blockHeight 区块高度
   *
   * swap
   * @param {Sha256=} params.genesisOutpointTxIdSwap 在和其他同类Token合约进行swap时，指定Token合约的genesisOutpoint TxId
   * @param {number=} params.genesisOutpointIdxSwap 在和其他同类Token合约进行swap时，指定Token合约的genesisOutpoint Index
   * @param {number=} params.genesisOutputIdxSwap 在和其他同类Token合约进行swap时，指定Token合约的genesisOutputIdx
   * @param {number=} params.amountSwap 在和其他同类Token合约进行swap时，要求的其他token数量
   *
   * sell
   * @param {number=} params.satoshiAmountSell 在出售Token时，要求的bsv数量
   */
  constructor({ scriptCode, dataType, ownerPkh, tokenAmount,
                blockHeader, blockHeight,
                genesisOutpointTxIdSwap, genesisOutpointIdxSwap, genesisOutputIdxSwap, amountSwap,
                satoshiAmountSell }) {
    this.dataType = dataType;
    this.ownerPkh = ownerPkh;
    this.tokenAmount = tokenAmount;

    // mint
    this.blockHeader = blockHeader;
    this.blockHeight = blockHeight;

    // swap
    this.genesisOutpointTxIdSwap = genesisOutpointTxIdSwap
    this.genesisOutpointIdxSwap = genesisOutpointIdxSwap
    this.genesisOutputIdxSwap = genesisOutputIdxSwap
    this.amountSwap = amountSwap;

    // sell
    this.satoshiAmountSell = satoshiAmountSell;
  }

  dump() {
    let payload = "";

    if (this.dataType == MINT) {
      payload = this.blockHeader + num2bin(this.blockHeight, DataLen8) + this.dataType;
    } else if (this.dataType == TRANSFER) {
      payload = toHex(this.ownerPkh) + num2bin(this.tokenAmount, DataLen8) + this.dataType;
    } else if (this.dataType == SWAP) {
      payload =
        toHex(this.ownerPkh) +
        num2bin(this.tokenAmount, DataLen8) +

        this.genesisOutpointTxIdSwap +
        num2bin(this.genesisOutpointIdxSwap, DataLen4) +
        num2bin(this.genesisOutputIdxSwap, DataLen4) +
        num2bin(this.amountSwap, DataLen8) +

        this.dataType;
    } else if (this.dataType == SELL) {
      payload = toHex(this.ownerPkh) + num2bin(this.tokenAmount, DataLen8) + num2bin(this.satoshiAmountSell, DataLen8) + this.dataType;
    }
    return payload;
  }
}


module.exports = {
  PayloadToken,
};
