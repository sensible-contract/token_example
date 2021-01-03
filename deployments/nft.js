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
  console.log("pkhIssuer:", toHex(issuerPkh));

  const receiver1PrivKey = new bsv.PrivateKey.fromWIF("cRCsQuoGatjXDdzjYhb1r3RH8LDqCEvjNc8gYS7HcnodPf44guQG");
  const receiver1Pk = bsv.PublicKey.fromPrivateKey(receiver1PrivKey);
  const receiver1Pkh = bsv.crypto.Hash.sha256ripemd160(receiver1Pk.toBuffer());
  console.log("pkhReceiver1:", toHex(receiver1Pkh));

  const receiver2PrivKey = new bsv.PrivateKey.fromWIF("cNLWqaouzifBDZL44C7beiSUWt8k4R6Gj2fnG2tgqdAVSHpYv8He");
  const receiver2Pk = bsv.PublicKey.fromPrivateKey(receiver2PrivKey);
  const receiver2Pkh = bsv.crypto.Hash.sha256ripemd160(receiver2Pk.toBuffer());
  console.log("pkhReceiver2:", toHex(receiver2Pkh));


  try {
    // 设置要执行的命令
    let command = "buy"

    const nft = new NFT(true);

    // 设置溯源信息
    const genesisOutpointTxId = "2b7d40a28769f9ca420c7150ce906eaf1470899394b3a586f9374a7aa6781599";
    const genesisOutpointIdx = 1;
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
      // 设置当前tokenId
      let currTokenId = 2;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "5d41f3518fe18f7d4eb4b92815c721856766d61dac7bf995fc5a12a2c2efd7f4";
      let preUtxoOutputIndex = 0;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "f9a3e8532006ef83017c00aa6af00aa1ed8f60d942903a1a13df212672b8b69e";
      let spendByOutputIndex = 0

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

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

      let txid = await sendTx(txIssue);
      // let txid = txIssue.id;
      let txHex = txIssue.serialize();
      console.log("issue txid: ", txid);
      console.log("issue txhex: ", txHex);
    }


    //////////////////////////////////////////////////////////////// transfer
    if (command == "transfer") {
      // 设置当前tokenId
      let currTokenId = 2;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "f9a3e8532006ef83017c00aa6af00aa1ed8f60d942903a1a13df212672b8b69e";
      let preUtxoOutputIndex = 1;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "475760b4e6d1c0756db31ff163648aefe14e868731892d9812547d60ffae454c";
      let spendByOutputIndex = 0;

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

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

      let txid = await sendTx(txTransfer);
      // let txid = txTransfer.id;
      let txHex = txTransfer.serialize();
      console.log("transfer txid: ", txid);
      console.log("transfer txhex: ", txHex);
    }


    //////////////////////////////////////////////////////////////// make swap
    if (command == "makeswap") {
      // 设置当前tokenId
      let currTokenId = 1;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "5d41f3518fe18f7d4eb4b92815c721856766d61dac7bf995fc5a12a2c2efd7f4";
      let preUtxoOutputIndex = 1;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "fa7a57385310457144c2075594992327222166f45faade85a718dcdd76ab9a9b";
      let spendByOutputIndex = 0;

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      ////////////////
      // 创建并解锁transfer
      let codeWithGenesisPartHashSwap = bsv.crypto.Hash.sha256sha256(bsv.util.buffer.hexToBuffer("00"));

      let txTransferPl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: receiver2Pkh, tokenId: currTokenId });
      let txSwapToken = await nft.makeTxSwapToken(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txTransferPl),
        },
        {
          outputOwnerPkh: receiver2Pkh,
          codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
          tokenAmountSwap: 1,
          outputTokenId: currTokenId,
          changeAddress: dummyAddress,
        });

      // unlock
      let verifyData = await nft.unlockTxSwapToken(
        {
          tx: txSwapToken,
          pl: _.cloneDeep(txTransferPl),
          codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
          tokenAmountSwap: 1,
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

      let txid = await sendTx(txSwapToken);
      // let txid = txSwapToken.id;
      let txHex = txSwapToken.serialize();
      console.log("make swap txid: ", txid);
      console.log("make swap txhex: ", txHex);
    }


    //////////////////////////////////////////////////////////////// cancel swap
    if (command == "cancelswap") {
      // 设置当前tokenId
      let currTokenId = 1;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "fa7a57385310457144c2075594992327222166f45faade85a718dcdd76ab9a9b";
      let preUtxoOutputIndex = 0;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "6ad0aa795b07598c2b7eba40f1f437311b14fc14886fd2dfc389a0751edf0694";
      let spendByOutputIndex = 0;

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      ////////////////
      // 创建并解锁transfer
      let codeWithGenesisPartHashSwap = bsv.crypto.Hash.sha256sha256(bsv.util.buffer.hexToBuffer("00"));

      let txSwapTokenPl = new PayloadNFT({
        dataType: SWAP,
        ownerPkh: receiver2Pkh,
        tokenId: currTokenId,
        codeWithGenesisPartHashSwap: codeWithGenesisPartHashSwap,
        tokenAmountSwap: 1,
      });
      let txCancelSwapToken = await nft.makeTxCancelSwapToken(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txSwapTokenPl),
        },
        {
          outputOwnerPkh: receiver2Pkh,
          outputTokenId: currTokenId,
          changeAddress: dummyAddress,
        });

      // unlock
      let verifyData = await nft.unlockTxCancelSwapToken(
        {
          tx: txCancelSwapToken,
          pl: _.cloneDeep(txSwapTokenPl),
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

      let txid = await sendTx(txCancelSwapToken);
      // let txid = txCancelSwapToken.id;
      let txHex = txCancelSwapToken.serialize();
      console.log("cancel swap txid: ", txid);
      console.log("cancel swap txhex: ", txHex);
    }


    //////////////////////////////////////////////////////////////// sell
    if (command == "sell") {
      // 设置当前tokenId
      let currTokenId = 1;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "6ad0aa795b07598c2b7eba40f1f437311b14fc14886fd2dfc389a0751edf0694";
      let preUtxoOutputIndex = 0;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "eb9f56d95b55a1e8d800aab3e6e78017f204d32bbd23d7a6c0e9b12b50bdbca9";
      let spendByOutputIndex = 0;

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      ////////////////
      // 创建并解锁transfer
      const satoshiAmountSell = 10000;

      let txTransferPl = new PayloadNFT({ dataType: TRANSFER, ownerPkh: receiver2Pkh, tokenId: currTokenId });
      let txSell = await nft.makeTxSell(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txTransferPl),
        },
        {
          satoshiAmountSell: satoshiAmountSell,
          outputOwnerPkh: receiver2Pkh,
          outputTokenId: currTokenId,
          changeAddress: dummyAddress,
        });

      // unlock
      let verifyData = await nft.unlockTxSell(
        {
          tx: txSell,
          pl: _.cloneDeep(txTransferPl),
          satoshiAmountSell: satoshiAmountSell,
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

      let txid = await sendTx(txSell);
      // let txid = txSell.id;
      let txHex = txSell.serialize();
      console.log("sell txid: ", txid);
      console.log("sell txhex: ", txHex);
    }


    //////////////////////////////////////////////////////////////// cancel sell
    if (command == "cancelsell") {
      // 设置当前tokenId
      let currTokenId = 3;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "3d0309fc4fd11b823d91837038ded3bb89676c7be51327086b178635c80b5ae4";
      let preUtxoOutputIndex = 0;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "da1974c3dd062c64a82d740d12ad4f80a367e24d465377f6a0014edfdea65b69";
      let spendByOutputIndex = 0;

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      ////////////////
      // 创建并解锁transfer
      const satoshiAmountSell = 10000;

      let txSellPl = new PayloadNFT({ dataType: SELL, ownerPkh: receiver2Pkh, satoshiAmountSell: satoshiAmountSell, tokenId: currTokenId });
      let txCancelSell = await nft.makeTxCancelSell(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txSellPl),
        },
        {
          outputOwnerPkh: receiver2Pkh,
          outputTokenId: currTokenId,
          changeAddress: dummyAddress,
        });

      // unlock
      let verifyData = await nft.unlockTxCancelSell(
        {
          tx: txCancelSell,
          pl: _.cloneDeep(txSellPl),
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

      let txid = await sendTx(txCancelSell);
      // let txid = txCancelSell.id;
      let txHex = txCancelSell.serialize();
      console.log("cancel sell txid: ", txid);
      console.log("cancel sell txhex: ", txHex);
    }


    //////////////////////////////////////////////////////////////// buy
    if (command == "buy") {
      // 设置当前tokenId
      let currTokenId = 1;
      // 设置prevPrevTxId，计算溯源u4
      let preUtxoTxId = "eb9f56d95b55a1e8d800aab3e6e78017f204d32bbd23d7a6c0e9b12b50bdbca9";
      let preUtxoOutputIndex = 0;
      // 设置prevTxId，为需要花费的utxo
      let spendByTxId = "d38320835e1ea2bdb033f4ae82bd0fa880d0506aaf19f9e17f368ff0f29679be";
      let spendByOutputIndex = 0;

      let preUtxoTxHex = await woc.getRawTxData(preUtxoTxId);
      let spendByTxHex = await woc.getRawTxData(spendByTxId);

      ////////////////
      // 创建并解锁transfer
      const satoshiAmountSell = 10000;
      const buyerSatoshis = 5000;

      let txSellPl = new PayloadNFT({ dataType: SELL, ownerPkh: receiver2Pkh, satoshiAmountSell: satoshiAmountSell, tokenId: currTokenId });
      let txBuy = await nft.makeTxBuy(
        {
          prevTxId: spendByTxId,
          outputIndex: spendByOutputIndex,
          pl: _.cloneDeep(txSellPl),
        },
        {
          outputOwnerPkh: receiver1Pkh,
          buyerSatoshis: buyerSatoshis,
          inputOwnerPkh: receiver2Pkh,
          satoshiAmountSell: satoshiAmountSell,
          outputTokenId: currTokenId,
          changeAddress: dummyAddress,
        });

      // unlock
      let verifyData = await nft.unlockTxBuy(
        {
          tx: txBuy,
          pl: _.cloneDeep(txSellPl),
          outputOwnerPkh: receiver1Pkh,
          buyerSatoshis: buyerSatoshis,
          changePkh: dummyPkh,
        },
        {
          index: preUtxoOutputIndex,
          txId: preUtxoTxId,
          txHex: preUtxoTxHex,
          byTxId: spendByTxId,
          byTxHex: spendByTxHex,
        });

      let txid = await sendTx(txBuy);
      // let txid = txBuy.id;
      let txHex = txBuy.serialize();
      console.log("buy txid: ", txid);
      console.log("buy txhex: ", txHex);
    }

    console.log("Succeeded on testnet");
  } catch (error) {
    console.log("Failed on testnet");
    showError(error);
  }
})();
