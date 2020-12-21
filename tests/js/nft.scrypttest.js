const { expect } = require("chai");
const { bsv, buildContractClass, signTx, toHex, getPreimage, num2bin, Ripemd160, PubKey, SigHashPreimage, Sig, Bytes } = require("scryptlib");
const { inputIndex, inputSatoshis, compileContract, DataLen, dummyTxId, satoTxSigUTXOSpendBy, satoTxSigUTXO } = require("../../helper");

// const { privateKey } = require("../../privateKey");

const outputAmount = 10000;
const DataLen8 = 8;
const DataLen4 = 4;

describe("Test sCrypt contract NFT In Javascript", () => {
  let token, lockingScriptCodePart;

  let makeTxP2pk, makeTxGenesis, makeTxIssue, makeTxTransfer, makeTxTransferBurn;

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

  const Signature = bsv.crypto.Signature;
  // Note: ANYONECANPAY
  const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

  const currTokenId = 0;

  // dataType
  const dataTypeIssue = "00";
  const dataTypeTransfer = "01";

  // genesis
  const genisisOutpointTxId = "ce913e7b636784f91567132ecb8dcbab48700b08eda166dc98e2ce07689fd285";
  const genesisOutpointWithOutputIdx = "85d29f6807cee298dc66a1ed080b7048abcb8dcb2e136715f98467637b3e91ce" + num2bin(0, DataLen4) + num2bin(0, DataLen4);

  const genesisPreTxHex =
    "0200000001cc8e4f0c398e8a477a09ff940ae82e48d14d6786cb6fc351c90163ee52a90d4b000000006a47304402200243afe8dda86318d7a0557f9dc683a0ce64c18c1e60ba64031ef2bf64a53a8a022063e42f1e97e0bccd76600f43bbf61b8b48589d9bf3aa759a59ef266705b0c4cc012103cb8f9734f4dc2e423dad83d59f7f2e823a9ab4df0e1fa1b18690f8bd0376cd9bffffffff038e94f300000000001976a91405a24d44e37cae0f4e231514c3ad512d313b141688ac0000000000000000166a146f6d6e69000000000000001f00000001cdb2948022020000000000001976a9140b3257cef14c3c6ee1725f5edb7e1da63318fcc088ac00000000";

  before(() => {
    const Token = buildContractClass(compileContract("nft.scrypt"));

    token = new Token(
      0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn
    );
    console.log("issuer pubkey", toHex(publicKeyIssuer));

    // code part
    lockingScriptCodePart = token.codePart.toASM();

    // start
    makeTxP2pk = () => {
      let txnew = new bsv.Transaction();
      txnew.addInput(
        new bsv.Transaction.Input({ prevTxId: dummyTxId, outputIndex: 0, script: "" }),
        bsv.Script.fromASM("OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG"),
        100001000
      );
      txnew.addOutput(
        new bsv.Transaction.Output({
          script: bsv.Script.fromASM("OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG"),
          satoshis: 100000000,
        })
      );
      return txnew;
    };

    // Genesis
    makeTxGenesis = (prevTxId, pkhTheIssuer, lastTokenId) => {
      let txnew = new bsv.Transaction();
      txnew.addInput(
        new bsv.Transaction.Input({ prevTxId: prevTxId, outputIndex: 0, script: "" }),
        bsv.Script.fromASM("OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG"),
        100001000
      );
      // genesisLockingScript
      const newLockingScript = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhTheIssuer) + num2bin(lastTokenId, DataLen8) + dataTypeIssue].join(" ");
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.fromASM(newLockingScript), satoshis: 100000000 }));
      return txnew;
    };

    // make tx issue
    makeTxIssue = (prevIssueTxId, pkhNewReceiver, pkhTheIssuer, pkChange, lastTokenId, nextTokenId) => {
      let txnew = new bsv.Transaction();
      // input 0
      // genesisLockingScript
      const newLockingScript = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhTheIssuer) + num2bin(lastTokenId, DataLen8) + dataTypeIssue].join(" ");
      txnew.addInput(new bsv.Transaction.Input({ prevTxId: prevIssueTxId, outputIndex: 0, script: "" }), bsv.Script.fromASM(newLockingScript), 100000000);
      // input 1
      txnew.addInput(
        new bsv.Transaction.Input({ prevTxId: "ecf64be3b407af50add3ace3438458347b0c93e06ca26262f83f7a24c77baf68", outputIndex: 0, script: "" }),
        bsv.Script.fromASM("OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG"),
        100001000
      );
      // output 0
      const newLockingScript0 = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhTheIssuer) + num2bin(nextTokenId, DataLen8) + dataTypeIssue].join(" ");
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.fromASM(newLockingScript0), satoshis: 100000000 }));
      // output 1
      const newLockingScript1 = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhNewReceiver) + num2bin(nextTokenId, DataLen8) + dataTypeTransfer].join(" ");
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.fromASM(newLockingScript1), satoshis: 50000000 }));
      // output 2
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(pkChange), satoshis: 50000000 }));
      return txnew;
    };

    // make tx transfer
    makeTxTransfer = (prevTransferTxId, pkhOwner, pkhNewReceiver, pkChange, lastTokenId, transferTokenId) => {
      let txnew = new bsv.Transaction();
      // input 0
      // prev output 1
      const prevTransferLockingScript1 = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhOwner) + num2bin(lastTokenId, DataLen8) + dataTypeTransfer].join(" ");
      txnew.addInput(new bsv.Transaction.Input({ prevTxId: prevTransferTxId, outputIndex: 1, script: "" }), bsv.Script.fromASM(prevTransferLockingScript1), 50000000);
      // input 1
      txnew.addInput(
        new bsv.Transaction.Input({ prevTxId: "ecf64be3b407af50add3ace3438458347b0c93e06ca26262f83f7a24c77baf68", outputIndex: 0, script: "" }),
        bsv.Script.fromASM("OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG"),
        50001000
      );
      // output 0
      const newLockingScript0 = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhNewReceiver) + num2bin(transferTokenId, DataLen8) + dataTypeTransfer].join(" ");
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.fromASM(newLockingScript0), satoshis: 50000000 }));
      // output 1
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(pkChange), satoshis: 50000000 }));
      return txnew;
    };

    // make tx transfer burn
    makeTxTransferBurn = (prevTransferTxId, pkhOwner, pkChange, lastTokenId) => {
      let txnew = new bsv.Transaction();
      // input 0
      // prev output 1
      const prevTransferLockingScript1 = [lockingScriptCodePart, genesisOutpointWithOutputIdx, toHex(pkhOwner) + num2bin(lastTokenId, DataLen8) + dataTypeTransfer].join(" ");
      txnew.addInput(new bsv.Transaction.Input({ prevTxId: prevTransferTxId, outputIndex: 1, script: "" }), bsv.Script.fromASM(prevTransferLockingScript1), 50000000);
      // input 1
      txnew.addInput(
        new bsv.Transaction.Input({ prevTxId: "ecf64be3b407af50add3ace3438458347b0c93e06ca26262f83f7a24c77baf68", outputIndex: 0, script: "" }),
        bsv.Script.fromASM("OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG"),
        1000
      );
      // output 0
      txnew.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(pkChange), satoshis: 50000000 }));

      return txnew;
    };
  });

  it("should succeed when one new token is issued", async () => {
    const testIssue = async (privKey, pkhGenesisIssuer, pkhNewReceiver, pkhNewIssuer, nextTokenId, followGenesis) => {
      let newGenisisOutpointTxId = genisisOutpointTxId;
      let newGenesisPreTxHex = genesisPreTxHex;
      if (followGenesis != true) {
        let txP2pk = makeTxP2pk();
        newGenisisOutpointTxId = txP2pk.id;
        newGenesisPreTxHex = txP2pk.serialize();
      }

      let txGenesis = makeTxGenesis(newGenisisOutpointTxId, pkhGenesisIssuer, currTokenId);
      let txIssue = makeTxIssue(txGenesis.id, pkhNewReceiver, pkhNewIssuer, publicKeyIssuer, currTokenId, nextTokenId);

      // 设置校验环境
      token.setDataPart(genesisOutpointWithOutputIdx + " " + toHex(pkhGenesisIssuer) + num2bin(currTokenId, DataLen8) + dataTypeIssue);
      token.txContext = { tx: txIssue, inputIndex, inputSatoshis: 100000000 };

      // 计算preimage
      const preimage = getPreimage(txIssue, token.lockingScript.toASM(), 100000000, inputIndex, sighashType);
      // 计算签名
      const sig = signTx(txIssue, privKey, token.lockingScript.toASM(), 100000000, inputIndex, sighashType);

      /*
      console.log("issue tx:", txIssue.serialize())
      console.log("toHex(preimage):", toHex(preimage))
      console.log("toHex(sig):", toHex(sig))
      console.log("toHex(pkhReceiver1):", toHex(pkhReceiver1))
      */

      // 获取Oracle签名
      let sigInfo = await satoTxSigUTXOSpendBy(newGenisisOutpointTxId, 0, txGenesis.id, newGenesisPreTxHex, txGenesis.serialize());
      // console.log("satoTxSigUTXOSpendBy:", sigInfo)
      const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
      const preTxOutpointMsg = sigInfo.payload;
      const preTxOutpointPadding = sigInfo.padding;

      // 验证
      return token.issue(
        new SigHashPreimage(toHex(preimage)),
        preTxOutpointSig,
        new Bytes(preTxOutpointMsg),
        new Bytes(preTxOutpointPadding),
        new Sig(toHex(sig)),
        new PubKey(toHex(publicKeyIssuer)),
        new Ripemd160(toHex(receiver1Pkh)),
        50000000,
        new Ripemd160(toHex(pkhNewIssuer)),
        50000000
      );
    };

    let verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 1, true);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;

    // copy utxo must fail
    verifyData = await testIssue(issuerPrivKey, issuerPkh, receiver1Pkh, issuerPkh, currTokenId + 1, false);
    result = verifyData.verify();
    expect(result.success, result.error).to.be.false;

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
    const testTransfer = async (privKeyIssue, privKeyTranse, pkhGenesisIssuer, pkhNewIssuer, pkhOwner1, pkhOwner2, pkOwner1, transTokenId) => {
      let txGenesis = makeTxGenesis(genisisOutpointTxId, pkhGenesisIssuer, currTokenId);
      // console.log("genesis txid:", txGenesis.id)

      let txIssue = makeTxIssue(txGenesis.id, pkhOwner1, pkhNewIssuer, publicKeyIssuer, currTokenId, currTokenId + 1);
      let txTransfer = makeTxTransfer(txIssue.id, pkhOwner1, pkhOwner2, pkOwner1, currTokenId + 1, transTokenId);

      token.setDataPart(genesisOutpointWithOutputIdx + " " + toHex(pkhOwner1) + num2bin(currTokenId + 1, DataLen8) + dataTypeTransfer);
      token.txContext = { tx: txTransfer, inputIndex, inputSatoshis: 50000000 };

      // 计算preimage
      const preimage = getPreimage(txTransfer, token.lockingScript.toASM(), 50000000, inputIndex, sighashType);
      // 计算签名
      const sig = signTx(txTransfer, privKeyTranse, token.lockingScript.toASM(), 50000000, inputIndex, sighashType);

      /*
        console.log("current tx:", txTransfer.serialize())
        console.log("toHex(preimage):", toHex(preimage))
        console.log("toHex(sig):", toHex(sig))
        console.log("toHex(pkOwner1):", toHex(pkOwner1))
        console.log("toHex(pkhOwner1):", toHex(pkhOwner1))
      */

      // 获取Oracle签名
      let sigInfo = await satoTxSigUTXOSpendBy(txGenesis.id, 0, txIssue.id, txGenesis.serialize(), txIssue.serialize());
      // console.log("satoTxSigUTXOSpendBy:", sigInfo)
      const preTxOutpointSig = BigInt("0x" + sigInfo.sigBE);
      const preTxOutpointMsg = sigInfo.payload;
      const preTxOutpointPadding = sigInfo.padding;

      return token.transfer(
        new SigHashPreimage(toHex(preimage)),
        preTxOutpointSig,
        new Bytes(preTxOutpointMsg),
        new Bytes(preTxOutpointPadding),
        new Sig(toHex(sig)),
        new PubKey(toHex(pkOwner1)),
        new Ripemd160(toHex(pkhOwner2)),
        50000000,
        new Ripemd160(toHex(pkhOwner1)),
        50000000
      );
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
    const testBurn = async (privKeyTranse, pkhGenesisIssuer, pkhNewIssuer, pkhOwner, pkOwner, transferTokenId) => {
      let txGenesis = makeTxGenesis(genisisOutpointTxId, pkhGenesisIssuer, currTokenId);
      // console.log("genesis txid:", txGenesis.id)

      let txIssue = makeTxIssue(txGenesis.id, pkhOwner, pkhNewIssuer, publicKeyIssuer, currTokenId, transferTokenId);
      let txTransferBurn = makeTxTransferBurn(txIssue.id, pkhOwner, pkOwner, transferTokenId);

      token.setDataPart(genesisOutpointWithOutputIdx + " " + toHex(pkhOwner) + num2bin(transferTokenId, DataLen8) + dataTypeTransfer);
      token.txContext = {
        tx: txTransferBurn,
        inputIndex,
        inputSatoshis: 50000000,
      };

      // 计算preimage
      const preimage = getPreimage(txTransferBurn, token.lockingScript.toASM(), 50000000, inputIndex, sighashType);
      // 计算签名
      const sig = signTx(txTransferBurn, privKeyTranse, token.lockingScript.toASM(), 50000000, inputIndex, sighashType);

      /*
        console.log("current tx:", txTransfer.serialize())
        console.log("toHex(preimage):", toHex(preimage))
        console.log("toHex(sig):", toHex(sig))
        console.log("toHex(pkOwner):", toHex(pkOwner))
        console.log("toHex(pkhReceiver1):", toHex(pkhReceiver1))
      */

      return token.burn(new SigHashPreimage(toHex(preimage)), new Sig(toHex(sig)), new PubKey(toHex(pkOwner)), new Ripemd160(toHex(pkhOwner)), 50000000);
    };

    let verifyData = await testBurn(receiver1PrivKey, issuerPkh, issuerPkh, receiver1Pkh, receiver1Pk, currTokenId + 1);
    let result = verifyData.verify();
    expect(result.success, result.error).to.be.true;
  });
});
