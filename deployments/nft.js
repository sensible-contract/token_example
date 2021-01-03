const _ = require("lodash");
const { bsv, toHex, num2bin, Ripemd160, SigHashPreimage, PubKey, Sig, Bytes } = require("scryptlib");
const {
  DataLen,
  DataLen4,
  DataLen8,
  createLockingTx,
  createPayByOthersTx,
  sendTx,
  reverseEndian,
  unlockP2PKHInput,
  showError,
} = require("../helper");
const { NFT } = require("../forge/nft");
const { PayloadNFT, ISSUE, TRANSFER, SWAP, SELL } = require("../forge/payload_nft");
const WhatsOnChain = require("whatsonchain");

const { privateKey } = require("../privateKey");

const dummyAddress = privateKey.toAddress();
const dummyPublicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const dummyPkh = bsv.crypto.Hash.sha256ripemd160(dummyPublicKey.toBuffer());

(async () => {
  const woc = new WhatsOnChain("testnet");
  const issuerPrivKey = new bsv.PrivateKey.fromWIF("cPbFsSjFjCbfzTRc8M4nKNGhVJspwnPQAcDhdJgVr3Pdwpqq7LfA");
  const issuerPk = bsv.PublicKey.fromPrivateKey(issuerPrivKey);
  const issuerPkh = bsv.crypto.Hash.sha256ripemd160(issuerPk.toBuffer());
  console.log("pkhIssuer:", toHex(issuerPkh)); // d3e990e3d6802a033c9b8d3c2ceda56dc0638126

  const receiver1PrivKey = new bsv.PrivateKey.fromWIF("cRCsQuoGatjXDdzjYhb1r3RH8LDqCEvjNc8gYS7HcnodPf44guQG");
  const receiver1Pk = bsv.PublicKey.fromPrivateKey(receiver1PrivKey);
  const receiver1Pkh = bsv.crypto.Hash.sha256ripemd160(receiver1Pk.toBuffer());
  console.log("pkhReceiver1:", toHex(receiver1Pkh)); // 2edcd18e10de1a646169b19e3c83ec404c8685bd

  const receiver2PrivKey = new bsv.PrivateKey.fromWIF("cNLWqaouzifBDZL44C7beiSUWt8k4R6Gj2fnG2tgqdAVSHpYv8He");
  const receiver2Pk = bsv.PublicKey.fromPrivateKey(receiver2PrivKey);
  const receiver2Pkh = bsv.crypto.Hash.sha256ripemd160(receiver2Pk.toBuffer());
  console.log("pkhReceiver2:", toHex(receiver2Pkh)); // 36d163b7bb8808077b768091fe93c3be55f44b15

  const genesisOutpointTxId = "2b7d40a28769f9ca420c7150ce906eaf1470899394b3a586f9374a7aa6781599";
  const genesisOutpointIdx = 1;
  const genesisOutpoint = reverseEndian(genesisOutpointTxId) + num2bin(genesisOutpointIdx, DataLen4);
  const genesisPreTxHex = await woc.getRawTxData(genesisOutpointTxId);

  console.log("genesis Tx outpoint: ", genesisOutpoint);

  try {
    // 设置要执行的命令
    let command = "transfer"

    const nft = new NFT(true);

    // 设置溯源信息
    nft.setTxGenesisPart({ prevTxId: genesisOutpointTxId, outputIndex: genesisOutpointIdx });

    //////////////////////////////////////////////////////////////// 创建Genesis
    if (command == "genesis") {
      let currTokenId = 0;

      let txGenesis = await nft.makeTxGenesis({
        prevTxId: genesisOutpointTxId,
        outputIssuerPkh: issuerPkh,
        outputTokenId: currTokenId,
      });

      txGenesis.sign(privateKey);

      let genesisTxid = await sendTx(txGenesis);
      // let genesisTxid = txGenesis.id;
      console.log("genesis txid: ", genesisTxid);
      console.log("genesis txhex: ", txGenesis.serialize());
    }

    //////////////////////////////////////////////////////////////// 发行
    if (command == "issue") {
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoOutputIndex = 0;
      let preUtxoTxId = "5d41f3518fe18f7d4eb4b92815c721856766d61dac7bf995fc5a12a2c2efd7f4";
      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);

      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "f9a3e8532006ef83017c00aa6af00aa1ed8f60d942903a1a13df212672b8b69e";
      let spendByOutputIndex = 0
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      // 设置当前tokenId
      let currTokenId = 2;

      // 改好上面3处，即可解锁(spendByTxId, spendByOutputIndex)

      ////////////////
      // 创建并解锁issue
      let txIssuePl = new PayloadNFT({ dataType: ISSUE, ownerPkh: issuerPkh, tokenId: currTokenId });
      let txIssue = await nft.makeTxIssue(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txIssuePl),
        },
        {
          outputOwnerPkh: receiver1Pkh,
          outputTokenId: currTokenId + 1,
          changeAddress: dummyAddress,
        });
      // unlock
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
          index: preUtxoOutputIndex,
          txId: preUtxoTxId,
          txHex: preUtxoTxHex,
          byTxId: spendByTxId,
          byTxHex: spendByTxHex,
        });

      let issueTxid = await sendTx(txIssue);
      // let issueTxid = txIssue.id;
      let issueTxHex = txIssue.serialize();
      console.log("issue txid: ", issueTxid);
      console.log("issue txhex: ", issueTxHex);
    }


    //////////////////////////////////////////////////////////////// transfer
    if (command == "transfer") {
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoOutputIndex = 1;
      let preUtxoTxId = "f9a3e8532006ef83017c00aa6af00aa1ed8f60d942903a1a13df212672b8b69e";
      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);

      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "475760b4e6d1c0756db31ff163648aefe14e868731892d9812547d60ffae454c";
      let spendByOutputIndex = 0;
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      // 设置当前tokenId
      let currTokenId = 2;

      // 改好上面3处，即可解锁(spendByTxId, spendByOutputIndex)

      ////////////////
      // 创建并解锁transfer
      let txTransferPl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: receiver2Pkh, tokenId: currTokenId });
      let txTransfer = await nft.makeTxTransfer(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txTransferPl),
        },
        {
          outputOwnerPkh: receiver1Pkh,
          outputTokenId: currTokenId,
          changeAddress: dummyAddress,
        });

      // unlock
      let verifyData = await nft.unlockTxTransfer(
        {
          tx: txTransfer,
          pl: _.cloneDeep(txTransferPl),
          outputOwnerPkh: receiver1Pkh,
          changePkh: dummyPkh,
        },
        {
          privKeyTransfer: receiver2PrivKey,
          inputOwnerPk: receiver2Pk,
        },
        {
          index: preUtxoOutputIndex,
          txId: preUtxoTxId,
          txHex: preUtxoTxHex,
          byTxId: spendByTxId,
          byTxHex: spendByTxHex,
        });

      let transferTxid = await sendTx(txTransfer);
      // let transferTxid = txTransfer.id;
      let transferTxHex = txTransfer.serialize();
      console.log("transfer txid: ", transferTxid);
      console.log("transfer txhex: ", transferTxHex);
    }

    console.log("Succeeded on testnet");
  } catch (error) {
    console.log("Failed on testnet");
    showError(error);
  }
})();
