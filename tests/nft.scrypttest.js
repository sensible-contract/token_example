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

  before(() => {});

  const currTokenId = 0;

  // 创建Genesis之前的Tx
  let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
  let genesisOutpointTxId = txP2pk.id;
  let genesisPreTxHex = txP2pk.serialize();

  // 再创建Genesis Tx
  let txGenesis = nft.makeTxGenesis({
    prevTxId: genesisOutpointTxId,
    outputIndex: 0,
    outputIssuerPkh: issuerPkh,
    outputTokenId: currTokenId,
  });

  // 然后创建Issue Tx
  let txIssue = nft.makeTxIssue(
    {
      prevTxId: txGenesis.id,
      outputIndex: 0,
      outputOwnerPkh: receiver1Pkh,
      changeAddress: dummyAddress,
    },
    {
      inputIssuerPkh: issuerPkh,
      inputTokenId: currTokenId,
      outputTokenId: currTokenId + 1,
    }
  );

  // 创建Transfer Tx
  let txTransfer = nft.makeTxTransfer(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      outputOwnerPkh: receiver2Pkh,
      changeAddress: dummyAddress,
    },
    {
      inputOwnerPkh: receiver1Pkh,
      inputTokenId: currTokenId + 1,
      outputTokenId: currTokenId + 1,
    }
  );

  // 创建Burn Tx
  let txTransferBurn = nft.makeTxTransferBurn(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      changeAddress: dummyAddress,
    },
    {
      inputOwnerPkh: receiver1Pkh,
      inputTokenId: currTokenId + 1,
    }
  );

  let codeWithGenesisPartHashSwap = bsv.crypto.Hash.sha256sha256(bsv.util.buffer.hexToBuffer("00"));
  // 创建Swap Tx
  let txSwapToken = nft.makeTxSwapToken(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
      tokenAmountSwap: 1,
      changeAddress: dummyAddress,
    },
    { inputOwnerPkh: receiver1Pkh, inputTokenId: currTokenId + 1, outputOwnerPkh: receiver1Pkh, outputTokenId: currTokenId + 1 }
  );

  // 创建 cancel swapToken Tx
  let txCancelSwapToken = nft.makeTxCancelSwapToken(
    { prevTxId: txSwapToken.id, outputIndex: 0, changeAddress: dummyAddress },
    {
      codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
      tokenAmountSwap: 1,
      inputOwnerPkh: receiver1Pkh,
      inputTokenId: currTokenId + 1,
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
    }
  );

  const satoshiAmountSell = 100000;
  // 创建sell Tx
  let txSell = nft.makeTxSell(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      satoshiAmountSell: satoshiAmountSell,
      changeAddress: dummyAddress,
    },
    {
      inputOwnerPkh: receiver1Pkh,
      inputTokenId: currTokenId + 1,
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
    }
  );

  // 创建取消sell Tx
  let txCancelSell = nft.makeTxCancelSell(
    {
      prevTxId: txSell.id,
      outputIndex: 0,
      changeAddress: dummyAddress,
    },
    {
      inputOwnerPkh: receiver1Pkh,
      satoshiAmountSell: satoshiAmountSell,
      inputTokenId: currTokenId + 1,
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
    }
  );

  const buyerSatoshis = 5000;
  // 创建购买buy Tx
  let txBuy = nft.makeTxBuy(
    { prevTxId: txSell.id, outputIndex: 0, outputOwnerPkh: receiver2Pkh, buyerSatoshis: buyerSatoshis, changeAddress: dummyAddress },
    { inputOwnerPkh: receiver1Pkh, satoshiAmountSell: satoshiAmountSell, inputTokenId: currTokenId + 1, outputTokenId: currTokenId + 1 }
  );

  it("should succeed when one new token is issued", async () => {
    /**
     * @type {IssueEnvs}
     */
    let envs = {
      privKeyIssuer: issuerPrivKey,
      publicKeyIssuer: publicKeyIssuer,
      inputIssuerPkh: issuerPkh,
      inputTokenId: currTokenId,
    };
    let testCaseEnvs = [];

    /* 先正常成功测试 */
    let envs0 = _.cloneDeep(envs);
    testCaseEnvs.push(envs0);

    // 再始测试各种情况

    // // copy utxo must fail
    // result = verifyData.verify();
    // expect(result.success, result.error).to.be.false;

    // issuer must not change
    let envs1 = _.cloneDeep(envs);
    envs1.inputIssuerPkh = receiver1Pkh;
    testCaseEnvs.push(envs1);

    // unauthorized key
    let envs2 = _.cloneDeep(envs);
    envs2.privKeyIssuer = receiver1PrivKey;
    testCaseEnvs.push(envs2);

    // mismatched next token ID
    let envs3 = _.cloneDeep(envs);
    envs3.inputTokenId = currTokenId + 2;
    testCaseEnvs.push(envs3);

    // test
    for (let idx = 0; idx < testCaseEnvs.length; idx++) {
      let verifyData = await nft.unlockTxIssue(
        {
          txIssue: txIssue,
          outputReceiverPkh: receiver1Pkh,
          changePkh: dummyPkh,
        },
        testCaseEnvs[idx],
        {
          preTxId: txGenesis.id,
          preTxHex: txGenesis.serialize(),
          prevPrevTxId: genesisOutpointTxId,
          prevPrevOutputIndex: 0,
          prevPrevTxHex: genesisPreTxHex,
        }
      );

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
     * @type {TransEnvs}
     */
    let envs = {
      privKeyTransfer: receiver1PrivKey,
      inputOwnerPkh: receiver1Pkh,
      inputOwnerPk: receiver1Pk,
      inputTokenId: currTokenId + 1,
    };

    let testCaseEnvs = [];

    /* 先正常成功测试 */
    let envs0 = _.cloneDeep(envs);
    testCaseEnvs.push(envs0);

    // 再始测试各种情况
    // unauthorized key
    let envs1 = _.cloneDeep(envs);
    envs1.privKeyTransfer = receiver2PrivKey;
    testCaseEnvs.push(envs1);

    // token ID must not change
    let envs2 = _.cloneDeep(envs);
    envs2.inputTokenId = currTokenId + 2;
    testCaseEnvs.push(envs2);

    // test
    for (let idx = 0; idx < testCaseEnvs.length; idx++) {
      let verifyData = await nft.unlockTxTransfer(
        {
          txTransfer: txTransfer,
          outputOwnerPkh: receiver2Pkh,
          changePkh: dummyPkh,
        },
        testCaseEnvs[idx],
        {
          preTxId: txIssue.id,
          preTxHex: txIssue.serialize(),
          prevPrevTxId: txGenesis.id,
          prevPrevOutputIndex: 0,
          prevPrevTxHex: txGenesis.serialize(),
        }
      );

      let result = verifyData.verify();
      if (idx == 0) {
        expect(result.success, result.error).to.be.true;
      } else {
        expect(result.success, result.error).to.be.false;
      }
    }
  });

  it("should success when receiver burn the token", async () => {
    /* 先正常成功测试 */
    let verifyData = await nft.unlockTxTransferBurn(
      {
        txTransferBurn: txTransferBurn,
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
        inputOwnerPkh: receiver1Pkh,
        inputTokenId: currTokenId + 1,
      }
    );

    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
