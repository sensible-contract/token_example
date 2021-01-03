const { expect } = require("chai");
const _ = require("lodash");
const { bsv, toHex } = require("scryptlib");
const { NFT } = require("../forge/nft");
const { PayloadNFT, ISSUE, TRANSFER, SWAP, SELL } = require("../forge/payload_nft");

const { privateKey } = require("../privateKey");

const dummyAddress = privateKey.toAddress();
const dummyPublicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPublicKey.toBuffer());

describe("Test sCrypt contract NFT In Javascript", async () => {
  // const privateKey1 = new bsv.PrivateKey.fromRandom('testnet')
  const issuerPrivKey = new bsv.PrivateKey.fromWIF("cPbFsSjFjCbfzTRc8M4nKNGhVJspwnPQAcDhdJgVr3Pdwpqq7LfA");
  const issuerPk = bsv.PublicKey.fromPrivateKey(issuerPrivKey);
  const issuerPkh = bsv.crypto.Hash.sha256ripemd160(issuerPk.toBuffer());
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

  //////////////////////////////////////////////////////////////// payload
  let txIssuePl = new PayloadNFT({ dataType: ISSUE, ownerPkh: issuerPkh, tokenId: currTokenId });
  let txTransferPl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: receiver1Pkh, tokenId: currTokenId + 1 });

  //////////////////////////////////////////////////////////////// 创建Genesis之前的Tx
  let txP2pk = await nft.makeTxP2pk({ outputSatoshis: 100000000 });
  let genesisOutpointTxId = txP2pk.id;
  let genesisPreTxHex = txP2pk.serialize();

  //////////////////////////////////////////////////////////////// 再创建Genesis Tx

  // 设置溯源信息
  nft.setTxGenesisPart({ prevTxId: genesisOutpointTxId, outputIndex: 0 });

  let txGenesis = await nft.makeTxGenesis({
    prevTxId: genesisOutpointTxId,
    outputIssuerPkh: issuerPkh,
    outputTokenId: currTokenId,
  });

  //////////////////////////////////////////////////////////////// 然后创建Issue Tx
  let txIssue = await nft.makeTxIssue(
    {
      prevTxId: txGenesis.id,
      outputIndex: 0,
      pl: _.cloneDeep(txIssuePl),
    },
    {
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when one new token is issued", async () => {
    let verifyData = await nft.unlockTxIssue(
      {
        tx: txIssue,
        pl: _.cloneDeep(txIssuePl),
        outputOwnerPkh: receiver1Pkh,
        changePkh: dummyPkh,
      },
      {
        privKeyIssuer: issuerPrivKey,
        publicKeyIssuer: issuerPk,
      },
      {
        index: 0,
        txId: genesisOutpointTxId,
        txHex: genesisPreTxHex,
        byTxId: txGenesis.id,
        byTxHex: txGenesis.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建Transfer Tx
  let txTransfer = await nft.makeTxTransfer(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      pl: _.cloneDeep(txTransferPl),
    },
    {
      outputOwnerPkh: receiver2Pkh,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when a token is transferred", async () => {
    let verifyData = await nft.unlockTxTransfer(
      {
        tx: txTransfer,
        pl: _.cloneDeep(txTransferPl),
        outputOwnerPkh: receiver2Pkh,
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
      },
      {
        index: 0,
        txId: txGenesis.id,
        txHex: txGenesis.serialize(),
        byTxId: txIssue.id,
        byTxHex: txIssue.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建Swap Tx
  let codeWithGenesisPartHashSwap = bsv.crypto.Hash.sha256sha256(bsv.util.buffer.hexToBuffer("00"));
  let txSwapToken = await nft.makeTxSwapToken(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      pl: _.cloneDeep(txTransferPl),
    },
    {
      outputOwnerPkh: receiver1Pkh,
      codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
      tokenAmountSwap: 1,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when a token need swap", async () => {
    let verifyData = await nft.unlockTxSwapToken(
      {
        tx: txSwapToken,
        pl: _.cloneDeep(txTransferPl),
        codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
        tokenAmountSwap: 1,
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
      },
      {
        index: 0,
        txId: txGenesis.id,
        txHex: txGenesis.serialize(),
        byTxId: txIssue.id,
        byTxHex: txIssue.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建 cancel swapToken Tx
  let txCancelSwapTokenPl = new PayloadNFT({
    dataType: SWAP,
    ownerPkh: receiver1Pkh,
    tokenId: currTokenId + 1,
    codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
    tokenAmountSwap: 1,
  });
  let txCancelSwapToken = await nft.makeTxCancelSwapToken(
    {
      prevTxId: txSwapToken.id,
      outputIndex: 0,
      pl: _.cloneDeep(txCancelSwapTokenPl),
    },
    {
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when a token cancel swap", async () => {
    let verifyData = await nft.unlockTxCancelSwapToken(
      {
        tx: txCancelSwapToken,
        pl: _.cloneDeep(txCancelSwapTokenPl),
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
      },
      {
        index: 1,
        txId: txIssue.id,
        txHex: txIssue.serialize(),
        byTxId: txSwapToken.id,
        byTxHex: txSwapToken.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建sell Tx
  const satoshiAmountSell = 100000;
  let txSell = await nft.makeTxSell(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      pl: _.cloneDeep(txTransferPl),
    },
    {
      satoshiAmountSell: satoshiAmountSell,
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when a token need sell", async () => {
    let verifyData = await nft.unlockTxSell(
      {
        tx: txSell,
        pl: _.cloneDeep(txTransferPl),
        satoshiAmountSell: satoshiAmountSell,
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
      },
      {
        index: 0,
        txId: txGenesis.id,
        txHex: txGenesis.serialize(),
        byTxId: txIssue.id,
        byTxHex: txIssue.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建取消sell Tx
  let txSellPl = new PayloadNFT({ dataType: SELL, ownerPkh: receiver1Pkh, satoshiAmountSell: satoshiAmountSell, tokenId: currTokenId + 1 });
  let txCancelSell = await nft.makeTxCancelSell(
    {
      prevTxId: txSell.id,
      outputIndex: 0,
      pl: _.cloneDeep(txSellPl),
    },
    {
      outputOwnerPkh: receiver1Pkh,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when a token cancel sell", async () => {
    let verifyData = await nft.unlockTxCancelSell(
      {
        tx: txCancelSell,
        pl: _.cloneDeep(txSellPl),
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
      },
      {
        index: 1,
        txId: txIssue.id,
        txHex: txIssue.serialize(),
        byTxId: txSell.id,
        byTxHex: txSell.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建购买buy Tx
  const buyerSatoshis = 5000;
  let txBuy = await nft.makeTxBuy(
    {
      prevTxId: txSell.id,
      outputIndex: 0,
      pl: _.cloneDeep(txSellPl),
    },
    {
      outputOwnerPkh: receiver2Pkh,
      buyerSatoshis: buyerSatoshis,
      inputOwnerPkh: receiver1Pkh,
      satoshiAmountSell: satoshiAmountSell,
      outputTokenId: currTokenId + 1,
      changeAddress: dummyAddress,
    }
  );
  it("should succeed when a token buy", async () => {
    let verifyData = await nft.unlockTxBuy(
      {
        tx: txBuy,
        pl: _.cloneDeep(txSellPl),
        outputOwnerPkh: receiver2Pkh,
        buyerSatoshis: buyerSatoshis,
        changePkh: dummyPkh,
      },
      {
        index: 1,
        txId: txIssue.id,
        txHex: txIssue.serialize(),
        byTxId: txSell.id,
        byTxHex: txSell.serialize(),
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });

  //////////////////////////////////////////////////////////////// 创建Burn Tx
  let txTransferBurnPl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: receiver1Pkh, tokenId: currTokenId + 1 });
  let txTransferBurn = await nft.makeTxTransferBurn(
    {
      prevTxId: txIssue.id,
      outputIndex: 1,
      pl: txTransferBurnPl,
    },
    {
      changeAddress: dummyAddress,
    }
  );
  it("should success when receiver burn the token", async () => {
    /* 先正常成功测试 */
    let verifyData = await nft.unlockTxTransferBurn(
      {
        tx: txTransferBurn,
        pl: txTransferBurnPl,
        changePkh: dummyPkh,
      },
      {
        privKeyTransfer: receiver1PrivKey,
        inputOwnerPk: receiver1Pk,
      }
    );
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
