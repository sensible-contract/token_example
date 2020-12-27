const { expect } = require('chai');
const { buildContractClass, Bytes } = require('scryptlib');
const { compileContract, loadDesc } = require('../helper');

describe('Test sCrypt contract RabinSignature In Javascript', () => {
  let rabin, result

  before(() => {
    const RabinSignature = buildContractClass(compileContract('rabin.scrypt'));
    rabin = new RabinSignature();
  });

  it('should return true', () => {
    // append "n" for big int
    result = rabin.verifySig(
        0x34ffccb0ddfeec36dfa26f796c4f924d056fa9937c04da1a195152ad2edcd07f91255b313e6435f86c3542c02d9854ed25a4506413e5f7e579c86c8546058847aea93e68996b50d4640ea69885116f003e3370190b64f378a22380e902745bf6a0a549d9fa2334044cc04737378c86be49c0606baa0da0e8442f9836aecc939dn,
        new Bytes('85d29f6807cee298dc66a1ed080b7048abcb8dcb2e136715f98467637b3e91ce02000000220200000000000076a9140b3257cef14c3c6ee1725f5edb7e1da63318fcc088ac'),
        new Bytes('0000'),
        0x3d7b971acdd7bff96ca34857e36685038d9c91e3af693cf9e71d170a8aac885b62dd4746fe7ebd7f3d7d16a51d63aa86a4256bdc853d999193ec3e614d4917e3dde9f6954d1784d5a2580f6fb130442e6a8ad0850aeaa100920fcab9176a05eb1aa3b5ee3e3dc75ae7cde3c25d350bba92956c8bacb0c735d39240c6442bab9dn
      ).verify()
    expect(result.success, result.error).to.be.true
  });

  it('should throw error with wrong padding', () => {
    result = rabin.verifySig(
        0x12f1dd2e0965dc433b0d32b86333b0fb432df592f6108803d7afe51a14a0e867045fe22af85862b8e744700920e0b7e430a192440a714277efb895b51120e4ccn,
        new Bytes('00112233445566778899aabbccddeeff'),
        new Bytes('00'),
        0x15525796ddab817a3c54c4bea4ef564f090c5909b36818c1c13b9e674cf524aa3387a408f9b63c0d88d11a76471f9f2c3f29c47a637aa60bf5e120d1f5a65221n
      ).verify()
    expect(result.success, result.error).to.be.false
  });

  it('should throw error with wrong signature', () => {
    result = rabin.verifySig(
        0xff12f1dd2e0965dc433b0d32b86333b0fb432df592f6108803d7afe51a14a0e867045fe22af85862b8e744700920e0b7e430a192440a714277efb895b51120e4ccn,
        new Bytes('00112233445566778899aabbccddeeff'),
        new Bytes('00000000'),
        0x15525796ddab817a3c54c4bea4ef564f090c5909b36818c1c13b9e674cf524aa3387a408f9b63c0d88d11a76471f9f2c3f29c47a637aa60bf5e120d1f5a65221n
      ).verify()
    expect(result.success, result.error).to.be.false
  });
});
