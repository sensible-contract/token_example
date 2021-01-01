# sCrypt Project Boilerplate
[![Build Status](https://travis-ci.com/sCrypt-Inc/boilerplate.svg?branch=master)](https://travis-ci.com/sCrypt-Inc/boilerplate)
## Prerequisites
Make sure you have the [sCrypt Visual Studio Extension](https://marketplace.visualstudio.com/items?itemName=bsv-scrypt.sCrypt) installed.

## Guide

[**sCrypt**](https://scryptdoc.readthedocs.io) is a high-level programming language for writing smart contracts on Bitcoin SV. This project provides examples to help developers learn and integrate sCrypt smart contracts to their Javascript-based projects. Our recommended procedure of developing smart contract based applications is as follows:

1. Contract Development and Test

The [sCrypt Visual Studio Extension](https://marketplace.visualstudio.com/items?itemName=bsv-scrypt.sCrypt) is a tool for developers to write, test, and debug sCrypt smart contracts.

2. Contract Integration and Application Launch

After developing and unit testing the smart contracts, the next step is to integrate them into your application which is written in other languages such as Javascript or Python. Integration tests should be run on Bitcoin SV [Testnet](https://test.whatsonchain.com/) or [Scaling Test Network(STN)](https://bitcoinscaling.io/) before launching the application to the public on mainnet.

## Quickstart
```
npm install
npm test
```

## Directory layout
For each contract `x`, a source file is at `contracts/x.scrypt`, a test file is at `tests/js/x.scrypttest.js`, and a deployment file is at `deployments/x.js`.
<pre>
.
├── contracts                       # sCrypt contract files
│   ├── rabin.scrypt                    # <a href="https://medium.com/coinmonks/access-external-data-from-bitcoin-smart-contracts-2ecdc7448c43">Rabin signature</a> to import off-chain data into a contract via oracle
│   ├── token.scrypt                    # <a href="https://medium.com/coinmonks/layer-1-tokens-on-bitcoin-sv-e78c8abf270d">Layer-1 tokens</a> by storing token map as contract state in a single UTXO
│   └── util.scrypt                     # utility functions and constants
├── deployments                     # examples to deploy contract and call its function on testnet
    └── fixture
        └── autoGen                     # contract description json files
└── tests                           # contract test files
    ├── js                              # Javascript unit tests
    └── ts                              # Typescript unit tests
</pre>

## How to write test for an sCrypt contract

The major steps to write a sCrypt test are exemplified by `tests/demo.scrypttest.js`.

1. Install and import / require [`scryptlib` libary](https://github.com/scrypt-sv/scryptlib), which is a javascript SDK for integrating sCrypt smart contract.

```
npm install scryptlib
```


```javascript
import { buildContractClass } from 'scryptlib';
```


2. Use the imported function `buildContractClass` to get a reflected contract, which has same properties and methods as defined in the specified sCrypt contract.

```javascript
// build a contract class
// either by compiling the contract from scratch
const Demo = buildContractClass(compileContract('demo.scrypt'))
// or from contract desc file if it's already generated from compilation
const Demo = buildContractClass(loadDesc('demo_desc.json'))
```

Note that `demo_desc.json` is the description file name of the compiled contract, which will be generated automatically if you run `npm run watch` and its name follows the rule `$contractName_desc.json`.

1. Initialize the contract.

```javascript
demo = new Demo(4, 7);
```

2. Write tests for the instantiated contract as you would do in Javascript.

```javascript
const result = demo.add(7 + 4).verify()
expect(result.success, result.error).to.be.true
```

## How to run tests locally

### Run using sCrypt Extension
Run unit tests file within the editor/explorer context menu.

![Screenshot](https://raw.githubusercontent.com/wiki/scrypt-sv/boilerplate/extension_screenshots/run_test_demo.gif)

**Note:** The test files must be suffixed by `.scrypttest.js` or `.scrypttest.ts`, otherwise the "Run sCrypt Test" option would not appear in the menu.

### Run from console
Tests could also be run from the console by executing `npm test`, just like regular Javascript/TypeScript tests.

## How to deploy contracts
1. Provide a private key with funds in `privateKey.js`
```javascript
const key = '$YOUR_PRIVATE_KEY_HERE'
```
2. Deploy a contract and call its function by issuing
```bash
node deployments/demo.js
```
Output like the following will appear in the console. And you have successfully deployed a contract and called its function on Bitcoin. Sweet!

```
locking txid:      8d58ff9067f5fa893b5c695179559e108ebf850d0ce4fd1e42bc872417ffd424
unlocking txid:    c60b57e93551a6c52282801130649c6a97edcca5d2b28b8b4ae2afe0ee59bf79
Succeeded on testnet
```
It is **strongly recommended** to test your contract on testnet first, before deploying it on mainnet. Default deployment is on testnet. To switch to mainnet, simply modify `API_PREFIX` in `helper.js`.
```javascript
const API_PREFIX = 'https://api.whatsonchain.com/v1/bsv/main'
```
Before deploying a contract, make sure the latest contract has been compiled to a [description json file](https://github.com/scrypt-sv/scryptlib#contract-description-file), which is what will get deployed. This could be done automatically by running a daemon process with command `npm run watch`. It will monitor a contract file's change and recompile it when necessary. All generated description files are located at `deployments/fixture/autoGen`. Make sure it's up to date with the contract before deployment.
