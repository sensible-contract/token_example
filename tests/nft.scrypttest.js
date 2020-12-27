const { expect } = require("chai");
const { bsv, toHex } = require("scryptlib");
const { NFT } = require("../forge/nft");

const { privateKey } = require("../privateKey");

const dummyAddress = privateKey.toAddress();
const dummyPublicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPublicKey.toBuffer());

describe("Test sCrypt contract NFT In Javascript", () => {
  /* 02fac240917b1bc22871af783b9a958661bc2b497b27f571a32fe6988e8ad2b38f */
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
     * 测试issue，先从0开始创建一连串的Tx，直到创建出包含`Issue`类型数据的锁定脚本；然后调用合约的unlock创建解锁脚本；
     * 即可测试合约或发布被解锁的合约Tx
     *
     * * 创建Genesis之前的Tx
     * * 再创建Genesis Tx
     * * 然后创建Issue Tx
     * * 最后解锁Issue Tx
     *
     * @param {PrivateKey} privKeyIssuer 发行人私钥
     * @param {Ripemd160} pkhGenesisIssuer 初始设置的发行人
     * @param {Ripemd160} pkhNewReceiver 新token的接收人
     * @param {Ripemd160} pkhNewIssuer issue合约内新产生的发行人，应当和pkhGenesisIssuer一致
     * @param {number} nextTokenId issue合约内新产生的tokenId
     * @param {Boolean} followGenesis 测试用，issue合约内utxo是否和Genesis outpoint一致
     */
    function testIssue(privKeyIssuer, pkhGenesisIssuer, pkhNewReceiver, pkhNewIssuer, nextTokenId, followGenesis) {
      let prevPrevTxId;
      let prevPrevTxHex;

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

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

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

    let verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 1, true);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;

    // // copy utxo must fail
    // verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 1, false);
    // result = verifyData.verify();
    // expect(result.success, result.error).to.be.false;

    // issuer must not change
    verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, receiver1Pkh, currTokenId + 1, true);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;

    // unauthorized key
    verifyData = await testIssue(receiver1PrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 1, true);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;

    // mismatched next token ID
    verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 2, true);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;
  });

  it("should succeed when a token is transferred", async () => {
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
     * @param {PrivateKey} privKeyIssue 发行人私钥
     * @param {PrivateKey} privKeyTransfer 接收人私钥
     * @param {Ripemd160} pkhGenesisIssuer 初始设置的发行人
     * @param {Ripemd160} pkhNewIssuer issue合约内新产生的发行人，应当和pkhGenesisIssuer一致
     * @param {Ripemd160} pkhOwner1 接收人1
     * @param {Ripemd160} pkhOwner2 接收人2
     * @param {Pubkey} pkOwner1 接收人1的公钥
     * @param {number} transTokenId 被trans的tokenId
     */
    function testTransfer(privKeyIssue, privKeyTransfer, pkhGenesisIssuer, pkhNewIssuer, pkhOwner1, pkhOwner2, pkOwner1, transTokenId) {
      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

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

    let verifyData = await testTransfer(issuerPrivKey, receiver1PrivKey, issuerPkh, issuerPkh, receiver1Pkh, issuerPkh, receiver1Pk, currTokenId + 1);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;

    // unauthorized key
    verifyData = await testTransfer(issuerPrivKey, issuerPrivKey, issuerPkh, issuerPkh, receiver1Pkh, issuerPkh, receiver1Pk, currTokenId + 1);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;

    // token ID must not change
    verifyData = await testTransfer(issuerPrivKey, receiver1PrivKey, issuerPkh, issuerPkh, receiver1Pkh, issuerPkh, receiver1Pk, currTokenId + 2);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;
  });

  it("should success when receiver burn the token", async () => {
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
     * @param {PrivateKey} privKeyTransfer 接收人私钥
     * @param {Ripemd160} pkhGenesisIssuer 初始设置的发行人
     * @param {Ripemd160} pkhNewIssuer issue合约内新产生的发行人，应当和pkhGenesisIssuer一致
     * @param {Ripemd160} pkhOwner 接收人
     * @param {Pubkey} pkOwner 接收人公钥
     * @param {number} transferTokenId 被销毁的tokenId
     */
    function testBurn(privKeyTransfer, pkhGenesisIssuer, pkhNewIssuer, pkhOwner, pkOwner, transferTokenId) {
      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

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

    let verifyData = await testBurn(receiver1PrivKey, issuerPkh, issuerPkh, receiver1Pkh, receiver1Pk, currTokenId + 1);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
