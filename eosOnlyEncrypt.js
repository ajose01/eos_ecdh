const ecc = require('eosjs-ecc');

let getKey = async () => {
  // Generate EOS test keys
  let eosPk1 = await ecc.PrivateKey.randomKey();
  let eosPk2 = await ecc.PrivateKey.randomKey()
  let eosPub1 = ecc.privateToPublic(eosPk1);
  let eosPub2 = ecc.privateToPublic(eosPk2);
  console.log("EOS USER 1: ", eosPub1);
  console.log("EOS USER 2: ", eosPub2);

  // Message
  let message = "Tacos via EOS";
  console.log("Message to encrypt: ", message);

  // EOS KEY1 - Encrypting
  console.log("EOS User 1 encrypting the message\n")
  let encryptedMessage = ecc.Aes.encrypt(eosPk1, eosPub2, message)
  let nonce = encryptedMessage.nonce.toString();
  let checksum = encryptedMessage.checksum;
  let messageHex = encryptedMessage.message.toString('hex');
  console.log("Items to send to user 2:\n", messageHex,nonce,checksum);



  // EOS KEY2 - Decrypting the message
  console.log("EOS User 2 decrypting the message\n");
  let messageBuffer = Buffer.from(messageHex, 'hex');
  let decryptedMessageBuffer = ecc.Aes.decrypt(eosPk2, eosPub1, nonce, messageBuffer, checksum);
  let decryptedMessage = decryptedMessageBuffer.toString();
  console.log("decrypted message: ", decryptedMessage);
  console.log("message match?: ", (message == decryptedMessage));
};

getKey();
