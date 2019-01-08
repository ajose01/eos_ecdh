const EC = require('elliptic').ec;
const hkdf = require('futoin-hkdf');
const aesjs = require('aes-js');
const ecc = require('eosjs-ecc');
let {PrivateKey, PublicKey, Signature, Aes, key_utils, config} = require('eosjs-ecc')

const ec = new EC('secp256k1');

let getKey = async () => {
  // Generate EOS test keys
  let eosPk1 = await PrivateKey.randomKey();
  let eosPk2 = await PrivateKey.randomKey()
  let eosPub1 = ecc.privateToPublic(eosPk1);
  let eosPub2 = ecc.privateToPublic(eosPk2);
  console.log("EOS USER 1: ", eosPub1);
  console.log("EOS USER 2: ", eosPub2);

  // EOS KEY1 - Generating shared key
  console.log("Scenario 1. EOS User 1 generating shared key via own PK, and User 2 public key\n")
  const key1 = ec.keyFromPrivate(eosPk1.toBuffer());
  // We simulate not knowing the other parties PK.
  let eosPubBuffer2 = ecc.PublicKey(eosPub2).toBuffer();
  const ecpub2 = ec.keyFromPublic(eosPubBuffer2);
  const pub2 = ecpub2.getPublic();
  console.log("PubKey2: ", pub2);
  const shared1 = key1.derive(pub2).toString(16);
  console.log("Shared key derived by EOS USER 1: ", shared1);

  // EOS KEY1 - Generating shared key
  console.log("Scenario 2. EOS User 2 generating shared key via own PK, and User 1 public key\n")
  const key2 = ec.keyFromPrivate(eosPk2.toBuffer());
  // We simulate not knowing the other parties PK.
  let eosPubBuffer1 = ecc.PublicKey(eosPub1).toBuffer();
  const ecpub1 = ec.keyFromPublic(eosPubBuffer1);
  const pub1 = ecpub1.getPublic();
  console.log("PubKey1: ", pub1);
  const shared2 = key2.derive(pub1).toString(16);
  console.log("Shared key derived by EOS USER 2: ", shared2);

  // Check that both users derived same shared key
  console.log("Shared key match?: ", (shared1 === shared2));

  // Convert shared key to AES valid key
  let key = hkdf(shared1, 16)

  let text = "Let's encrypt... secret taco meetup!"
  console.log("Test string: ", text)
  let textBytes = aesjs.utils.utf8.toBytes(text);
  let aesCtr = new aesjs.ModeOfOperation.ctr(key);
  let encryptedBytes = aesCtr.encrypt(textBytes);
  let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
  console.log("Encrypted text as it would be transmitted:\n", encryptedHex);

  // Time to decrypt
  console.log("Now going to decrypt...:\n", encryptedHex);

  let encryptedBytes2 = aesjs.utils.hex.toBytes(encryptedHex);
  // Use same shared key to decrypt
  let aesCtr2 = new aesjs.ModeOfOperation.ctr(key);
  let decryptedBytes = aesCtr2.decrypt(encryptedBytes2);
  let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  console.log("Decrypted text result: ", decryptedText);
};

getKey();
