const { bsv, buildContractClass, getPreimage, toHex, num2bin, Ripemd160, SigHashPreimage, signTx, PubKey, Sig, Bytes } = require("scryptlib");
const { DataLen, loadDesc, createLockingTx, createPayByOthersTx, sendTx, reverseEndian, satoTxSigUTXOSpendBy, unlockP2PKHInput, showError } = require("../helper");
const WhatsOnChain = require("whatsonchain");
// const { privateKey } = require("../privateKey");

const DataLen8 = 8;
const DataLen4 = 4;

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

  const Signature = bsv.crypto.Signature;
  const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

  const actionIssue = "00";
  const actionTransfer = "01";

  const genisisOutpointTxId = "0229e3505156e0456747a4dfdd66b48994223e75ed97e746fec84c018d12fcde";
  const genesisOutpoint = reverseEndian(genisisOutpointTxId) + num2bin(1, DataLen4);
  const genesisPreTxHex = await woc.getRawTxData(genisisOutpointTxId);

  console.log("genesis Tx outpoint: ", genesisOutpoint);

  try {
    const NonFungibleToken = buildContractClass(loadDesc("nft_desc.json"));
    const token = new NonFungibleToken(
      0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn
    );

    // set token id start
    let uniqTokenId = 0;

    // append state as passive data part, initial uniqTokenId
    token.setDataPart(genesisOutpoint + toHex(issuerPkh) + num2bin(uniqTokenId, DataLen8) + actionIssue);

    let issueSatoshis = 5000;
    const FEE = 15000;
    let transferSatoshis = 5000;

    if (false) {
      // lock fund to the script & issue the first token
      const lockingTx = await createLockingTx(privateKey.toAddress(), issueSatoshis, FEE);

      console.log("prevtxid:", toHex(lockingTx.inputs[0].prevTxId));
      console.log("prevtxindex:", lockingTx.inputs[0].outputIndex);

      lockingTx.outputs[0].setScript(token.lockingScript);
      lockingTx.sign(privateKey);
      let lockingTxid = await sendTx(lockingTx);
      // let lockingTxid = lockingTx.id;
      console.log("funding txid:      ", lockingTxid);
      console.log("funding txhex:      ", lockingTx.serialize());

      return;
    }

    // increment token ID and issue another new token
    /* from genesis issue */
    let preUtxoTxId = genisisOutpointTxId;
    let preUtxoOutputIndex = 1;
    let preUtxoTxHex = genesisPreTxHex;

    let issueTxid = "8ca9949e651fd84d670f6121af59d558dfce0addbf6aa59f5cdc888f9df4dcf3";
    let issueTxHex = await woc.getRawTxData(issueTxid);

    uniqTokenId = 0;
    let spendByIssueTxId = issueTxid;
    let spendByIssueTxHex = issueTxHex;

    /* from next issue */

    let lockingScript0, lockingScript1;
    if (false) {
      preUtxoTxId = issueTxid;
      preUtxoOutputIndex = 0;
      preUtxoTxHex = issueTxHex;

      issueTxid = "5d8fc6c58554f4669730552a6da63a564e946410453aa62bca54200974fa6ea6";
      issueTxHex = await woc.getRawTxData(issueTxid);

      uniqTokenId = 1;
      spendByIssueTxId = issueTxid;
      spendByIssueTxHex = issueTxHex;

      token.setDataPart(genesisOutpoint + toHex(issuerPkh) + num2bin(uniqTokenId, DataLen8) + actionIssue);
      const tx = await createPayByOthersTx(privateKey.toAddress());
      tx.addInput(
        new bsv.Transaction.Input({
          prevTxId: issueTxid,
          outputIndex: 0,
          script: "",
        }),
        token.lockingScript,
        issueSatoshis
      );

      const curInputIndex = tx.inputs.length - 1;

      // issue new token
      lockingScript0 = [token.codePart.toASM(), genesisOutpoint + toHex(issuerPkh) + num2bin(uniqTokenId + 1, DataLen8) + actionIssue].join(" ");
      tx.addOutput(
        new bsv.Transaction.Output({
          script: bsv.Script.fromASM(lockingScript0),
          satoshis: issueSatoshis,
        })
      );

      // transfer previous token to another receiver
      lockingScript1 = [token.codePart.toASM(), genesisOutpoint + toHex(receiver1Pkh) + num2bin(uniqTokenId + 1, DataLen8) + actionTransfer].join(" ");
      tx.addOutput(
        new bsv.Transaction.Output({
          script: bsv.Script.fromASM(lockingScript1),
          satoshis: transferSatoshis,
        })
      );
      tx.change(privateKey.toAddress()).fee(FEE);

      const changeAmount = tx.inputAmount - FEE - issueSatoshis - transferSatoshis;

      const preimage = getPreimage(tx, token.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);
      const sig1 = signTx(tx, privateKeyIssuer, token.lockingScript.toASM(), issueSatoshis, curInputIndex, sighashType);

      // 获取Oracle签名
      let sigInfo = await satoTxSigUTXOSpendBy(preUtxoTxId, preUtxoOutputIndex, spendByIssueTxId, preUtxoTxHex, spendByIssueTxHex);
      // console.log("satoTxSigUTXOSpendBy:", sigInfo);
      const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
      const preTxOutpointMsg = sigInfo.payload;
      const preTxOutpointPadding = sigInfo.padding;

      const unlockingScript = token
        .issue(
          new SigHashPreimage(toHex(preimage)),
          preTxOutpointSig,
          new Bytes(preTxOutpointMsg),
          new Bytes(preTxOutpointPadding),
          new Sig(toHex(sig1)),
          new PubKey(toHex(publicKeyIssuer)),
          new Ripemd160(toHex(receiver1Pkh)),
          transferSatoshis,
          new Ripemd160(toHex(issuerPkh)),
          changeAmount
        )
        .toScript();

      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      tx.inputs[curInputIndex].setScript(unlockingScript);
      issueTxid = await sendTx(tx);
      // issueTxid = tx.id;
      issueTxHex = tx.serialize();
      console.log("issue txid:       ", issueTxid);
      console.log("issue txhex:       ", issueTxHex);
      return;
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

      token.setDataPart(genesisOutpoint + toHex(receiver1Pkh) + num2bin(uniqTokenId, DataLen8) + actionTransfer);
      const tx = await createPayByOthersTx(privateKey.toAddress());
      tx.addInput(
        new bsv.Transaction.Input({
          prevTxId: issueTxid,
          outputIndex: 1,
          script: "",
        }),
        token.lockingScript,
        transferSatoshis
      );

      const curInputIndex = tx.inputs.length - 1;

      // transfer token to other one
      lockingScript0 = [token.codePart.toASM(), genesisOutpoint + toHex(receiver2Pkh) + num2bin(uniqTokenId, DataLen8) + actionTransfer].join(" ");
      tx.addOutput(
        new bsv.Transaction.Output({
          script: bsv.Script.fromASM(lockingScript0),
          satoshis: transferSatoshis,
        })
      );

      tx.change(privateKey.toAddress()).fee(FEE);

      const changeAmount = tx.inputAmount - FEE - transferSatoshis;

      const preimage = getPreimage(tx, token.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);
      const sig1 = signTx(tx, privateKeyReceiver1, token.lockingScript.toASM(), transferSatoshis, curInputIndex, sighashType);

      // 获取Oracle签名
      let sigInfo = await satoTxSigUTXOSpendBy(preUtxoTxId, preUtxoOutputIndex, spendByIssueTxId, preUtxoTxHex, spendByIssueTxHex);
      // console.log("satoTxSigUTXOSpendBy:", sigInfo);
      const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
      const preTxOutpointMsg = sigInfo.payload;
      const preTxOutpointPadding = sigInfo.padding;

      const unlockingScript = token
        .transfer(
          new SigHashPreimage(toHex(preimage)),
          preTxOutpointSig,
          new Bytes(preTxOutpointMsg),
          new Bytes(preTxOutpointPadding),
          new Sig(toHex(sig1)),
          new PubKey(toHex(publicKeyReceiver1)),
          new Ripemd160(toHex(receiver2Pkh)),
          transferSatoshis,
          new Ripemd160(toHex(issuerPkh)),
          changeAmount
        )
        .toScript();

      // unlock other p2pkh inputs
      for (let i = 0; i < curInputIndex; i++) {
        unlockP2PKHInput(privateKey, tx, i, sighashType);
      }
      tx.inputs[curInputIndex].setScript(unlockingScript);
      let transferTxid = await sendTx(tx);
      // let transferTxid = tx.id;
      let transferTxHex = tx.serialize();
      console.log("transfer txid:       ", transferTxid);
      console.log("transfer txhex:       ", transferTxHex);
      return;
    }

    console.log("Succeeded on testnet");
  } catch (error) {
    console.log("Failed on testnet");
    showError(error);
  }
})();
