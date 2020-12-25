const { bsv, buildContractClass, getPreimage, toHex, num2bin, Ripemd160, SigHashPreimage, signTx, PubKey, Sig, Bytes } = require("scryptlib");
const {
  DataLen,
  DataLen4,
  DataLen8,
  loadDesc,
  createLockingTx,
  createPayByOthersTx,
  sendTx,
  reverseEndian,
  satoTxSigUTXOSpendBy,
  unlockP2PKHInput,
  showError,
} = require("../helper");
const { NFT } = require("../../forge/nft");
const WhatsOnChain = require("whatsonchain");

// const { privateKey } = require("../privateKey");

(async () => {
  const woc = new WhatsOnChain("testnet");
  const privateKeyIssuer = new bsv.PrivateKey.fromWIF("cPbFsSjFjCbfzTRc8M4nKNGhVJspwnPQAcDhdJgVr3Pdwpqq7LfA");
  const publicKeyIssuer = bsv.PublicKey.fromPrivateKey(privateKeyIssuer);
  const issuerPkh = bsv.crypto.Hash.sha256ripemd160(publicKeyIssuer.toBuffer());
  console.log("pkhIssuer:", toHex(issuerPkh)); // d3e990e3d6802a033c9b8d3c2ceda56dc0638126

  const privateKey = privateKeyIssuer;

  const privateKeyReceiver1 = new bsv.PrivateKey.fromWIF("cRCsQuoGatjXDdzjYhb1r3RH8LDqCEvjNc8gYS7HcnodPf44guQG");
  const publicKeyReceiver1 = bsv.PublicKey.fromPrivateKey(privateKeyReceiver1);
  const receiver1Pkh = bsv.crypto.Hash.sha256ripemd160(publicKeyReceiver1.toBuffer());
  console.log("pkhReceiver1:", toHex(receiver1Pkh)); // 2edcd18e10de1a646169b19e3c83ec404c8685bd

  const privateKeyReceiver2 = new bsv.PrivateKey.fromWIF("cNLWqaouzifBDZL44C7beiSUWt8k4R6Gj2fnG2tgqdAVSHpYv8He");
  const publicKeyReceiver2 = bsv.PublicKey.fromPrivateKey(privateKeyReceiver2);
  const receiver2Pkh = bsv.crypto.Hash.sha256ripemd160(publicKeyReceiver2.toBuffer());
  console.log("pkhReceiver2:", toHex(receiver2Pkh)); // 36d163b7bb8808077b768091fe93c3be55f44b15

  const genesisOutpointTxId = "0229e3505156e0456747a4dfdd66b48994223e75ed97e746fec84c018d12fcde";
  const genesisOutpointIdx = 1;
  const genesisOutpoint = reverseEndian(genesisOutpointTxId) + num2bin(genesisOutpointIdx, DataLen4);
  const genesisOutpointValue = 100000;
  const genesisPreTxHex = await woc.getRawTxData(genesisOutpointTxId);

  console.log("genesis Tx outpoint: ", genesisOutpoint);

  try {
    const nft = new NFT(true);

    // set token id start
    let uniqTokenId = 0;

    if (true) {
      let txGenesis = nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIndex: genesisOutpointIdx,
        outputIssuerPkh: issuerPkh,
        outputTokenId: uniqTokenId,
        inputSatoshis: genesisOutpointValue,
      });

      console.log("prevtxid:", toHex(txGenesis.inputs[0].prevTxId));
      console.log("prevtxindex:", txGenesis.inputs[0].outputIndex);

      txGenesis.sign(privateKey);

      let genesisTxid = await sendTx(txGenesis);
      // let genesisTxid = txGenesis.id;
      console.log("genesis txid:      ", genesisTxid);
      console.log("genesis txhex:     ", txGenesis.serialize());
      // return;
    }

    // increment token ID and issue another new token
    /* from genesis issue */
    let preUtxoTxId = genesisOutpointTxId;
    let preUtxoOutputIndex = 1;
    let preUtxoTxHex = genesisPreTxHex;

    let issueTxid = "8ca9949e651fd84d670f6121af59d558dfce0addbf6aa59f5cdc888f9df4dcf3";
    let issueTxHex = await woc.getRawTxData(issueTxid);

    uniqTokenId = 0;
    let spendByIssueTxId = issueTxid;
    let spendByIssueTxHex = issueTxHex;

    /* from next issue */
    if (true) {
      preUtxoTxId = issueTxid;
      preUtxoOutputIndex = 0;
      preUtxoTxHex = issueTxHex;

      issueTxid = "5d8fc6c58554f4669730552a6da63a564e946410453aa62bca54200974fa6ea6";
      issueTxHex = await woc.getRawTxData(issueTxid);

      uniqTokenId = 1;
      spendByIssueTxId = issueTxid;
      spendByIssueTxHex = issueTxHex;

      let txIssue = nft.makeTxIssue({
        prevTxId: issueTxid,
        outputIndex: 0,
        inputIssuerPkh: issuerPkh,
        outputOwnerPkh: receiver1Pkh,
        thisChangePk: publicKeyIssuer,
        inputTokenId: uniqTokenId,
        outputTokenId: uniqTokenId + 1,
      });

      nft.unlockTxIssue({
        txIssue,
        preTxId: spendByIssueTxId,
        preTxHex: spendByIssueTxHex,
        preUtxoTxId,
        preUtxoOutputIndex,
        preUtxoTxHex,
        privKeyIssuer: privateKeyIssuer,
        publicKeyIssuer,
        inputIssuerPkh: issuerPkh,
        outputReceiverPkh: receiver1Pkh,
        pkhNewIssuer: issuerPkh,
        inputTokenId: uniqTokenId,
      });

      issueTxid = await sendTx(tx);
      // issueTxid = tx.id;
      issueTxHex = tx.serialize();
      console.log("issue txid:       ", issueTxid);
      console.log("issue txhex:      ", issueTxHex);
      //return;
    }

    // transfer token to publicKeyReceiver2
    if (true) {
      preUtxoTxId = issueTxid;
      preUtxoOutputIndex = 0;
      preUtxoTxHex = issueTxHex;

      issueTxid = "5d8fc6c58554f4669730552a6da63a564e946410453aa62bca54200974fa6ea6";
      issueTxHex = await woc.getRawTxData(issueTxid);

      uniqTokenId = 1;
      spendByIssueTxId = issueTxid;
      spendByIssueTxHex = issueTxHex;

      let txTransfer = nft.makeTxTransfer({
        prevTxId: issueTxid,
        outputIndex: 1,
        inputOwnerPkh: receiver1Pkh,
        outputOwnerPkh: receiver2Pkh,
        thisChangePk: publicKeyIssuer,
        inputTokenId: uniqTokenId,
        outputTokenId: uniqTokenId,
      });

      nft.unlockTxTransfer({
        txTransfer,
        preTxId: spendByIssueTxId,
        preTxHex: spendByIssueTxHex,
        preUtxoTxId,
        preUtxoOutputIndex,
        preUtxoTxHex,
        privKeyTransfer: privateKeyReceiver1,
        inputOwnerPkh: receiver1Pkh,
        outputOwnerPkh: receiver2Pkh,
        inputOwnerPk: publicKeyReceiver1,
        changePkh: publicKeyReceiver1,
        inputTokenId: uniqTokenId,
      });

      let transferTxid = await sendTx(tx);
      // let transferTxid = tx.id;
      let transferTxHex = tx.serialize();
      console.log("transfer txid:       ", transferTxid);
      console.log("transfer txhex:      ", transferTxHex);
      // return;
    }

    console.log("Succeeded on testnet");
  } catch (error) {
    console.log("Failed on testnet");
    showError(error);
  }
})();
