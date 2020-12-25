const { expect } = require("chai");
const { bsv, toHex } = require("scryptlib");
const { NFT } = require("../../forge/nft");

const { privateKey } = require("../../privateKey");

const dummyAddress = privateKey.toAddress();
const dummyPublicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPublicKey.toBuffer());

describe("Test sCrypt contract NFT In Javascript", () => {
  let nft;

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

  const currTokenId = 0;

  before(() => {
    nft = new NFT();
    console.log("issuer pubkey", toHex(publicKeyIssuer));
  });

  it("should succeed when one new token is issued", async () => {
    const testIssue = async (privKeyIssuer, pkhGenesisIssuer, pkhNewReceiver, pkhNewIssuer, nextTokenId, followGenesis) => {
      let preUtxoTxId;
      let preUtxoTxHex;

      if (followGenesis != true) {
        let fakeTxP2pk = nft.makeTxP2pk({ outputSatoshis: 200000000 });
        preUtxoTxId = fakeTxP2pk.id;
        preUtxoTxHex = fakeTxP2pk.serialize();
      }

      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();
      if (followGenesis) {
        preUtxoTxId = txP2pk.id;
        preUtxoTxHex = txP2pk.serialize();
      }

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

      let txIssue = nft.makeTxIssue({
        prevTxId: txGenesis.id,
        outputIndex: 0,
        inputIssuerPkh: pkhNewIssuer,
        outputOwnerPkh: pkhNewReceiver,
        changeAddress: dummyAddress,
        inputTokenId: currTokenId,
        outputTokenId: nextTokenId,
      });

      return nft.unlockTxIssue({
        txIssue,
        preTxId: txGenesis.id,
        preTxHex: txGenesis.serialize(),
        preUtxoTxId,
        preUtxoOutputIndex: 0,
        preUtxoTxHex,
        privKeyIssuer,
        publicKeyIssuer,
        inputIssuerPkh: pkhGenesisIssuer,
        outputReceiverPkh: receiver1Pkh,
        changePkh: dummyPkh,
        inputTokenId: currTokenId,
      });
    };

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
    const testTransfer = async (privKeyIssue, privKeyTransfer, pkhGenesisIssuer, pkhNewIssuer, pkhOwner1, pkhOwner2, pkOwner1, transTokenId) => {
      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

      let txIssue = nft.makeTxIssue({
        prevTxId: txGenesis.id,
        outputIndex: 0,
        inputIssuerPkh: pkhNewIssuer,
        outputOwnerPkh: pkhOwner1,
        changeAddress: dummyAddress,
        inputTokenId: currTokenId,
        outputTokenId: currTokenId + 1,
      });

      let txTransfer = nft.makeTxTransfer({
        prevTxId: txIssue.id,
        outputIndex: 1,
        inputOwnerPkh: pkhOwner1,
        outputOwnerPkh: pkhOwner2,
        changeAddress: dummyAddress,
        inputTokenId: currTokenId + 1,
        outputTokenId: transTokenId,
      });

      return nft.unlockTxTransfer({
        txTransfer,
        preTxId: txIssue.id,
        preTxHex: txIssue.serialize(),

        preUtxoTxId: txGenesis.id,
        preUtxoOutputIndex: 0,
        preUtxoTxHex: txGenesis.serialize(),

        privKeyTransfer,
        inputOwnerPkh: pkhOwner1,
        outputOwnerPkh: pkhOwner2,
        inputOwnerPk: pkOwner1,
        changePkh: dummyPkh,
        inputTokenId: currTokenId + 1,
      });
    };

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
    const testBurn = async (privKeyTransfer, pkhGenesisIssuer, pkhNewIssuer, pkhOwner, pkOwner, transferTokenId) => {
      let txP2pk = nft.makeTxP2pk({ outputSatoshis: 100000000 });
      let genesisOutpointTxId = txP2pk.id;

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: 0,
        outputIssuerPkh: pkhGenesisIssuer,
        outputTokenId: currTokenId,
      });

      let txIssue = nft.makeTxIssue({
        prevTxId: txGenesis.id,
        outputIndex: 0,
        inputIssuerPkh: pkhNewIssuer,
        outputOwnerPkh: pkhOwner,
        changeAddress: dummyAddress,
        inputTokenId: currTokenId,
        outputTokenId: transferTokenId,
      });

      let txTransferBurn = nft.makeTxTransferBurn({
        prevTxId: txIssue.id,
        outputIndex: 1,
        inputOwnerPkh: pkhOwner,
        changeAddress: dummyAddress,
        inputTokenId: transferTokenId,
      });

      return nft.unlockTxTransferBurn({
        txTransferBurn,
        privKeyTransfer,
        inputOwnerPkh: pkhOwner,
        inputOwnerPk: pkOwner,
        changePkh: dummyPkh,
        inputTokenId: transferTokenId,
      });
    };

    let verifyData = await testBurn(receiver1PrivKey, issuerPkh, issuerPkh, receiver1Pkh, receiver1Pk, currTokenId + 1);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
