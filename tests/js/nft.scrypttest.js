const { expect } = require("chai");
const { bsv, toHex } = require("scryptlib");
const { NFT } = require("../../forge/nft");

// const { privateKey } = require("../../privateKey");

describe("Test sCrypt contract NFT In Javascript", () => {
  let nft, token;

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

  const rabinPubKey = 0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn;
  before(() => {
    nft = new NFT(rabinPubKey);
    console.log("issuer pubkey", toHex(publicKeyIssuer));
  });

  it("should succeed when one new token is issued", async () => {
    const testIssue = async (privKeyIssuer, pkhGenesisIssuer, pkhNewReceiver, pkhNewIssuer, nextTokenId, followGenesis) => {
      let newGenisisOutpointTxId;
      let newGenesisPreTxHex;

      if (followGenesis != true) {
        let fakeTxP2pk = nft.makeTxP2pk({ inputSatoshis: 200002000, outputSatoshis: 200000000 });
        newGenisisOutpointTxId = fakeTxP2pk.id;
        newGenesisPreTxHex = fakeTxP2pk.serialize();
      }

      let txP2pk = nft.makeTxP2pk({ inputSatoshis: 100001000, outputSatoshis: 100000000 });
      let genisisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();
      if (followGenesis) {
        newGenisisOutpointTxId = txP2pk.id;
        newGenesisPreTxHex = txP2pk.serialize();
      }

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genisisOutpointTxId,
        outputIndex: 0,
        thisIssuerPkh: pkhGenesisIssuer,
        lastTokenId: currTokenId,
        inputSatoshis: 100001000,
        genesisSatoshis: 100000000,
      });

      let txIssue = nft.makeTxIssue({
        prevTxId: txGenesis.id,
        outputIndex: 0,
        thisOwnerPkh: pkhNewReceiver,
        thisIssuerPkh: pkhNewIssuer,
        thisChangePk: publicKeyIssuer,
        lastTokenId: currTokenId,
        nextTokenId: nextTokenId,
      });

      return nft.unlockTxIssue({
        txGenesis,
        txIssue,
        newGenisisOutpointTxId,
        newGenesisPreTxHex,
        privKeyIssuer,
        publicKeyIssuer,
        pkhGenesisIssuer,
        receiver1Pkh,
        pkhNewIssuer,
        currTokenId,
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
      let txP2pk = nft.makeTxP2pk({ inputSatoshis: 100001000, outputSatoshis: 100000000 });
      let genisisOutpointTxId = txP2pk.id;
      let genesisPreTxHex = txP2pk.serialize();

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genisisOutpointTxId,
        outputIndex: 0,
        thisIssuerPkh: pkhGenesisIssuer,
        lastTokenId: currTokenId,
        inputSatoshis: 100001000,
        genesisSatoshis: 100000000,
      });

      let txIssue = nft.makeTxIssue({
        prevTxId: txGenesis.id,
        outputIndex: 0,
        thisOwnerPkh: pkhOwner1,
        thisIssuerPkh: pkhNewIssuer,
        thisChangePk: publicKeyIssuer,
        lastTokenId: currTokenId,
        nextTokenId: currTokenId + 1,
      });

      let txTransfer = nft.makeTxTransfer({
        prevTxId: txIssue.id,
        outputIndex: 1,
        lastOwnerPkh: pkhOwner1,
        thisOwnerPkh: pkhOwner2,
        thisChangePk: pkOwner1,
        lastTokenId: currTokenId + 1,
        transferTokenId: transTokenId,
      });

      return nft.unlockTxTransfer({ txGenesis, txIssue, txTransfer, genisisOutpointTxId, genesisPreTxHex, privKeyTransfer, pkhOwner1, pkhOwner2, pkOwner1, currTokenId });
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
      let txP2pk = nft.makeTxP2pk({ inputSatoshis: 100001000, outputSatoshis: 100000000 });
      let genisisOutpointTxId = txP2pk.id;

      let txGenesis = nft.makeTxGenesis({
        prevTxId: genisisOutpointTxId,
        outputIndex: 0,
        thisIssuerPkh: pkhGenesisIssuer,
        lastTokenId: currTokenId,
        inputSatoshis: 100001000,
        genesisSatoshis: 100000000,
      });

      let txIssue = nft.makeTxIssue({
        prevTxId: txGenesis.id,
        outputIndex: 0,
        thisOwnerPkh: pkhOwner,
        thisIssuerPkh: pkhNewIssuer,
        thisChangePk: publicKeyIssuer,
        lastTokenId: currTokenId,
        nextTokenId: transferTokenId,
      });

      let txTransferBurn = nft.makeTxTransferBurn({
        prevTxId: txIssue.id,
        outputIndex: 1,
        lastOwnerPkh: pkhOwner,
        thisChangePk: pkOwner,
        lastTokenId: transferTokenId,
      });

      return nft.unlockTxTransferBurn({ txTransferBurn, privKeyTransfer, pkhOwner, pkOwner, transferTokenId });
    };

    let verifyData = await testBurn(receiver1PrivKey, issuerPkh, issuerPkh, receiver1Pkh, receiver1Pk, currTokenId + 1);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
