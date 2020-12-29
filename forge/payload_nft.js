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


const ISSUE = "00";
const TRANSFER = "01";
const SWAP = "02";
const SELL = "03";

/**
 * PayloadNFT
 */
class PayloadNFT {
  /**
   * 解析、构造NFT合约的数据部分
   *
   * @constructor
   *
   * @param {Object} params
   * @param {String=} params.scriptCode 合约代码部分
   * @param {string} params.dataType 数据类型，1字节
   * @param {Ripemd160} params.ownerPkh 所属人
   * @param {number} params.tokenId tokenId
   * @param {String=} params.codeWithGenesisPartHashSwap 在和Token合约进行swap时，指定Token合约的code前缀部分
   * @param {number=} params.amountSwap 在和Token合约进行swap时，要求的token数量
   * @param {number=} params.satoshiAmountSell 在出售NFT时，要求的bsv数量
   */
  constructor({ scriptCode, dataType, ownerPkh, tokenId, codeWithGenesisPartHashSwap, amountSwap, satoshiAmountSell }) {
    this.dataType = dataType;
    this.ownerPkh = ownerPkh;
    this.tokenId = tokenId;
    this.codeWithGenesisPartHashSwap = codeWithGenesisPartHashSwap;
    this.amountSwap = amountSwap;
    this.satoshiAmountSell = satoshiAmountSell;
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


module.exports = {
  PayloadNFT,
};
