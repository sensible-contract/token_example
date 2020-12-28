const { expect } = require("chai");
const _ = require("lodash");
const { bsv, toHex } = require("scryptlib");
const { NFT } = require("../forge/nft");

const { privateKey } = require("../privateKey");

const dummyAddress = privateKey.toAddress();
const dummyPublicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPublicKey.toBuffer());

describe("Test sCrypt contract NFT In Javascript", () => {
  // const privateKey1 = new bsv.PrivateKey.fromRandom('testnet')
  const issuerPrivKey = new bsv.PrivateKey.fromWIF("cPbFsSjFjCbfzTRc8M4nKNGhVJspwnPQAcDhdJgVr3Pdwpqq7LfA");
  const publicKeyIssuer = bsv.PublicKey.fromPrivateKey(issuerPrivKey);
  const issuerPkh = bsv.crypto.Hash.sha256ripemd160(publicKeyIssuer.toBuffer());
  console.log("pkhIssuer:", toHex(issuerPkh)); // d3e990e3d6802a033c9b8d3c2ceda56dc0638126
  console.log(`address: '${issuerPrivKey.toAddress()}'`);

  // const privateKeyReceiver1 = new bsv.PrivateKey.fromRandom("testnet");
  const receiver1PrivKey = new bsv.PrivateKey.fromWIF("cRCsQuoGatjXDdzjYhb1r3RH8LDqCEvjNc8gYS7HcnodPf44guQG");
  const receiver1Pk = bsv.PublicKey.fromPrivateKey(receiver1PrivKey);
  const receiver1Pkh = bsv.crypto.Hash.sha256ripemd160(receiver1Pk.toBuffer());
  console.log("pkhReceiver1:", toHex(receiver1Pkh)); // 2edcd18e10de1a646169b19e3c83ec404c8685bd
  console.log(`address: '${receiver1PrivKey.toAddress()}'`);

  // const privateKeyReceiver2 = new bsv.PrivateKey.fromRandom("testnet");
  const receiver2PrivKey = new bsv.PrivateKey.fromWIF("cNLWqaouzifBDZL44C7beiSUWt8k4R6Gj2fnG2tgqdAVSHpYv8He");
  const receiver2Pk = bsv.PublicKey.fromPrivateKey(receiver2PrivKey);
  const receiver2Pkh = bsv.crypto.Hash.sha256ripemd160(receiver2Pk.toBuffer());
  console.log("pkhReceiver2:", toHex(receiver2Pkh)); // 36d163b7bb8808077b768091fe93c3be55f44b15
  console.log(`address: '${receiver2PrivKey.toAddress()}'`);

  let nft = new NFT();
  const currTokenId = 0;

  before(() => {});

  it("should succeed when one new token is issued", async () => {
    /**
     * @typedef {Object} IssueParams
     * @property {PrivateKey} privKeyIssuer 发行人私钥
     * @property {Ripemd160} pkhGenesisIssuer 初始设置的发行人
     * @property {Ripemd160} pkhNewReceiver 新token的接收人
     * @property {Ripemd160} pkhNewIssuer issue合约内新产生的发行人，应当和pkhGenesisIssuer一致
     * @property {number} nextTokenId issue合约内新产生的tokenId
     * @property {Boolean} followGenesis 测试用，issue合约内utxo是否和Genesis outpoint一致
     */
    /**
     * 测试issue，先从0开始创建一连串的Tx，直到创建出包含`Issue`类型数据的锁定脚本；然后调用合约的unlock创建解锁脚本；
     * 即可测试合约，或发布被解锁的合约Tx
     *
     * * 创建Genesis之前的Tx
     * * 再创建Genesis Tx
     * * 然后创建Issue Tx
     * * 最后解锁Issue Tx
     *
     * @param {IssueParams} params
     */
    function testIssue({ privKeyIssuer, pkhGenesisIssuer, pkhNewReceiver, pkhNewIssuer, nextTokenId, followGenesis }) {
      let prevPrevTxId;
      let prevPrevTxHex;

      /* 创建genesis之前的Tx */
      if (followGenesis != true) {
        let fakeTxP2pk = nft.makeTxP2pk({ outputSatoshis: 200000000 });
        prevPrevTxId = fakeTxP2pk.id;
        prevPrevTxHex = fakeTxP2pk.serialize();
      }

      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();
      if (followGenesis) {
        prevPrevTxId = txP2pk.id;
        prevPrevTxHex = txP2pk.serialize();
      }

      /* 创建genesis Tx */
      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

      /* 创建Issue Tx */
      let txIssue = nft.makeTxIssue(
        {
          prevTxId: txGenesis.id,
          outputIndex: 0,
          outputOwnerPkh: pkhNewReceiver,
          changeAddress: dummyAddress,
        },
        {
          inputIssuerPkh: pkhNewIssuer,
          inputTokenId: currTokenId,
          outputTokenId: nextTokenId,
        }
      );

      /* 解锁Issue Tx */
      return nft.unlockTxIssue(
        {
          txIssue: txIssue,
          outputReceiverPkh: receiver1Pkh,
          changePkh: dummyPkh,
        },
        {
          privKeyIssuer: privKeyIssuer,
          publicKeyIssuer: publicKeyIssuer,
          inputIssuerPkh: pkhGenesisIssuer,
          inputTokenId: currTokenId,
        },
        {
          preTxId: txGenesis.id,
          preTxHex: txGenesis.serialize(),
          prevPrevTxId: prevPrevTxId,
          prevPrevOutputIndex: 0,
          prevPrevTxHex: prevPrevTxHex,
        }
      );
    }

    /**
     * @type {IssueParams}
     */
    let params = {
      privKeyIssuer: issuerPrivKey,
      pkhGenesisIssuer: issuerPkh,
      pkhNewReceiver: receiver1Pkh,
      pkhNewIssuer: issuerPkh,
      nextTokenId: currTokenId + 1,
      followGenesis: true,
    };
    let testCaseParams = [];

    /* 先正常成功测试 */    
    let params0 = _.cloneDeep(params);
    testCaseParams.push(params0)
    
    // 再始测试各种情况
    // // copy utxo must fail
    // verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 1, false);
    // result = verifyData.verify();
    // expect(result.success, result.error).to.be.false;

    // issuer must not change
    let params1 = _.cloneDeep(params);
    params1.pkhNewIssuer = receiver1Pkh;
    testCaseParams.push(params1)

    // unauthorized key
    let params2 = _.cloneDeep(params);
    params2.privKeyIssuer = receiver1PrivKey;
    testCaseParams.push(params2)

    // mismatched next token ID
    let params3 = _.cloneDeep(params);
    params3.nextTokenId = currTokenId + 2;
    testCaseParams.push(params3)

    // test
    for (let idx = 0; idx < testCaseParams.length; idx++) {
      let verifyData = await testIssue(testCaseParams[idx]);
      let result = verifyData.verify();
      if (idx == 0) {
        expect(result.success, result.error).to.be.true;
      } else {
        expect(result.success, result.error).to.be.false;
      }
    }
  });

  it("should succeed when a token is transferred", async () => {
    /**
     * @typedef {Object} TransParams
     *
     * @property {PrivateKey} privKeyIssue 发行人私钥
     * @property {PrivateKey} privKeyTransfer 接收人私钥
     * @property {Ripemd160} pkhGenesisIssuer 初始设置的发行人
     * @property {Ripemd160} pkhNewIssuer issue合约内新产生的发行人，应当和pkhGenesisIssuer一致
     * @property {Ripemd160} pkhOwner1 接收人1
     * @property {Ripemd160} pkhOwner2 接收人2
     * @property {Pubkey} pkOwner1 接收人1的公钥
     * @property {number} transTokenId 被trans的tokenId
     */
    /**
     * 测试transfer，先从0开始创建一连串的Tx，直到创建出包含`Transfer`类型数据的锁定脚本；然后调用合约的unlock创建解锁脚本；
     * 即可测试合约或发布被解锁的合约Tx
     *
     * * 创建Genesis之前的Tx
     * * 再创建Genesis Tx
     * * 然后创建Issue Tx
     * * 然后创建Transfer Tx
     * * 最后解锁Transfer Tx
     *
     * @param {TransParams} params
     */
    function testTransfer({ privKeyIssue, privKeyTransfer, pkhGenesisIssuer, pkhNewIssuer, pkhOwner1, pkhOwner2, pkOwner1, transTokenId }) {
      // 创建Genesis之前的Tx
      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();

      // 再创建Genesis Tx
      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

      // 然后创建Issue Tx
      let txIssue = nft.makeTxIssue(
        {
          prevTxId: txGenesis.id,
          outputIndex: 0,
          outputOwnerPkh: pkhOwner1,
          changeAddress: dummyAddress,
        },
        {
          inputIssuerPkh: pkhNewIssuer,
          inputTokenId: currTokenId,
          outputTokenId: currTokenId + 1,
        }
      );

      // 然后创建Transfer Tx
      let txTransfer = nft.makeTxTransfer(
        {
          prevTxId: txIssue.id,
          outputIndex: 1,
          outputOwnerPkh: pkhOwner2,
          changeAddress: dummyAddress,
        },
        {
          inputOwnerPkh: pkhOwner1,
          inputTokenId: currTokenId + 1,
          outputTokenId: transTokenId,
        }
      );

      // 最后解锁Transfer Tx
      return nft.unlockTxTransfer(
        {
          txTransfer: txTransfer,
          outputOwnerPkh: pkhOwner2,
          changePkh: dummyPkh,
        },
        {
          privKeyTransfer: privKeyTransfer,
          inputOwnerPkh: pkhOwner1,
          inputOwnerPk: pkOwner1,
          inputTokenId: currTokenId + 1,
        },
        {
          preTxId: txIssue.id,
          preTxHex: txIssue.serialize(),
          prevPrevTxId: txGenesis.id,
          prevPrevOutputIndex: 0,
          prevPrevTxHex: txGenesis.serialize(),
        }
      );
    }

    /* 先正常成功测试 */
    /**
     * @type {TransParams}
     */
    let params = {
      privKeyIssue: issuerPrivKey,
      privKeyTransfer: receiver1PrivKey,
      pkhGenesisIssuer: issuerPkh,
      pkhNewIssuer: issuerPkh,
      pkhOwner1: receiver1Pkh,
      pkhOwner2: issuerPkh,
      pkOwner1: receiver1Pk,
      transTokenId: currTokenId + 1,
    };
    let verifyData = await testTransfer(params);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;

    // 再始测试各种情况
    // unauthorized key
    params.privKeyTransfer = issuerPrivKey;
    verifyData = await testTransfer(params);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;
    // restore
    params.privKeyTransfer = receiver1PrivKey;

    // token ID must not change
    params.transTokenId = currTokenId + 2;
    verifyData = await testTransfer(params);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;
    // restore
    params.transTokenId = currTokenId + 1;
  });

  it("should success when receiver burn the token", async () => {
    /**
     * @typedef {Object} BurnParams
     *
     * @property {PrivateKey} privKeyTransfer 接收人私钥
     * @property {Ripemd160} pkhGenesisIssuer 初始设置的发行人
     * @property {Ripemd160} pkhNewIssuer issue合约内新产生的发行人，应当和pkhGenesisIssuer一致
     * @property {Ripemd160} pkhOwner 接收人
     * @property {Pubkey} pkOwner 接收人公钥
     * @property {number} transferTokenId 被销毁的tokenId
     */
    /**
     * 测试burn，先从0开始创建一连串的Tx，直到创建出包含`Transfer`类型数据的锁定脚本；然后调用合约的unlock创建解锁脚本；
     * 即可测试合约或发布被解锁的合约Tx
     *
     * * 创建Genesis之前的Tx
     * * 再创建Genesis Tx
     * * 然后创建Issue Tx
     * * 然后创建Burn Tx
     * * 最后解锁Burn Tx
     *
     * @param {BurnParams} params
     */
    function testBurn({ privKeyTransfer, pkhGenesisIssuer, pkhNewIssuer, pkhOwner, pkOwner, transferTokenId }) {
      // 创建Genesis之前的Tx
      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;

      // 再创建Genesis Tx
      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

      // 然后创建Issue Tx
      let txIssue = nft.makeTxIssue(
        {
          prevTxId: txGenesis.id,
          outputIndex: 0,
          outputOwnerPkh: pkhOwner,
          changeAddress: dummyAddress,
        },
        {
          inputIssuerPkh: pkhNewIssuer,
          inputTokenId: currTokenId,
          outputTokenId: transferTokenId,
        }
      );

      // 然后创建Burn Tx
      let txTransferBurn = nft.makeTxTransferBurn(
        {
          prevTxId: txIssue.id,
          outputIndex: 1,
          changeAddress: dummyAddress,
        },
        {
          inputOwnerPkh: pkhOwner,
          inputTokenId: transferTokenId,
        }
      );

      // 最后解锁Burn Tx
      return nft.unlockTxTransferBurn(
        {
          txTransferBurn: txTransferBurn,
          changePkh: dummyPkh,
        },
        {
          privKeyTransfer: privKeyTransfer,
          inputOwnerPk: pkOwner,
          inputOwnerPkh: pkhOwner,
          inputTokenId: transferTokenId,
        }
      );
    }

    /* 先正常成功测试 */
    let verifyData = await testBurn({
      privKeyTransfer: receiver1PrivKey,
      pkhGenesisIssuer: issuerPkh,
      pkhNewIssuer: issuerPkh,
      pkhOwner: receiver1Pkh,
      pkOwner: receiver1Pk,
      transferTokenId: currTokenId + 1,
    });
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
