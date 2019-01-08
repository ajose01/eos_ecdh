![Locks](https://cdn.steemitimages.com/DQmYb1GYUm6iRAksGi3acW36fVwfs6GQahioZjoMMSmuME3/image.png)
[Photo - @neonbrand via unsplash](https://unsplash.com/@neonbrand)

# Securing messages using EOS (and ECDH and AES)

_Disclaimer: I'm sharing as I'm learning... please use at your own risk, or better yet share in comments how to improve! Also, I will use terms as seed / password loosely, to illustrate the process._

Can we encrypt communication between two EOS users using the private / public keys already in our possession? YES! Well... with some caveats. ECC in itself is not an encryption algorithm. In EOS and other blockchains it is used to sign transactions, but not to obscure what is being signed. However, it can be leveraged to encrypt communications if we take a couple steps.

## Preface
We are going to do this first the long way, to learn a bit about the process. We'll finish with a simpler (and quicker) way using some existing EOS tooling (Skip to Step 5 if you want to just see that). This is in Javascript, so here's what we'll need:
```Javascript
const EC = require('elliptic').ec;
const hkdf = require('futoin-hkdf');
const aesjs = require('aes-js');
const ecc = require('eosjs-ecc');
```
We'll also generate some EOS keys for ourselves:
```Javascript
let eosPk1 = await PrivateKey.randomKey();
let eosPk2 = await PrivateKey.randomKey()
let eosPub1 = ecc.privateToPublic(eosPk1);
let eosPub2 = ecc.privateToPublic(eosPk2);
console.log("EOS USER 1: ", eosPub1);
console.log("EOS USER 2: ", eosPub2);
```

## Step 1 - Generate a shared encryption seed.

In order to encrypt our communications, we would usually need an encryption seed (for us encryption noobs, think something like a password) that we use to secure our communication. As long as both parties know the password, we can decrypt our message. The trick is having a common seed / pass that we never have to communicate to the other party. In crypto world, we already have enough keys to worry about! How can we accomplish this?

Enter [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman). Using this protocol, we can use our EOS (or any ECC) private key and the other parties EOS public key.

Here's the process assuming we are EOS user 1:
```Javascript
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
```
We'd do the reverse for the other user, and we would end up generating the same shared key #winning.

## Step 2 - Convert our shared key to a valid AES key / encryption seed.

Our shared key here needs to be converted to a seed we can use with AES. To do that we use a Key Derivation Function, in this case [HKDF](https://en.wikipedia.org/wiki/HKDF).

```Javascript
// Convert shared key to AES valid key
let key = hkdf(shared1, 16)
```

## Step 3 - Encrypt our message via AES

Now that we have a valid key to use for AES encryption, we can finally get to making our messages secret.
```Javascript
let text = "Let's encrypt... secret taco meetup!"
console.log("Test string: ", text)
let textBytes = aesjs.utils.utf8.toBytes(text);
let aesCtr = new aesjs.ModeOfOperation.ctr(key);
let encryptedBytes = aesCtr.encrypt(textBytes);
// We convert to hex to make it easy to transmit as text
let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
console.log("Encrypted text as it would be transmitted:\n", encryptedHex);
// Encrypted text as it would be transmitted:
// 9c27303372372cda33c70441f0960fde77fff9b118ddc64f2bcf027f3823da142f5e6baa

```
Here we could have used a nonce or a counter to add a bit more security to the messages we are sending or receiving.
```Javascript
// The counter is optional, and if omitted will begin at 1
let aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
```

## Step 4 - Decrypting message

The other user would have been able to generate the same shared key using the steps above. On receiving this message, they would now use that key to decrypt the message.
```Javascript
// Time to decrypt
console.log("Now going to decrypt...:\n", encryptedHex);

let encryptedBytes2 = aesjs.utils.hex.toBytes(encryptedHex);
// Use same shared key to decrypt
let aesCtr2 = new aesjs.ModeOfOperation.ctr(key);
let decryptedBytes = aesCtr2.decrypt(encryptedBytes2);
let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
console.log("Decrypted text result: ", decryptedText);
//Now going to decrypt...:
// 9c27303372372cda33c70441f0960fde77fff9b118ddc64f2bcf027f3823da142f5e6baa
//Decrypted text result:  Let's encrypt... secret taco meetup!
```
Wooohooo! We have communicated without letting prying eyes know what we wrote. 🌮🌮🌮

The full code to test this out is [here](https://github.com/ajose01/eos_ecdh/blob/master/eosEncrypt.js). Feel free to give it a try.

## Step 5 - EOS tooling makes it (somewhat) simpler.
Going through the steps above was a good exercise for me to learn how things are working under the hood, especially because I am interested in learning more about cryptography. However, there is a [simpler way](https://github.com/EOSIO/eosjs-ecc/issues/19) to do this via `eosjs-ecc`. Let's give it a whirl:

###### First we encrypt using the same keys generated earlier.
```Javascript
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
// Items to send to user 2:
// 28e2fa0c4bc8a339a5b7e096883e51fa 101379311011030238 1143290642
```
You'll notice that we will have to send over some additional items with the user aside from the message: nonce and checksum.
###### Now we can decrypt with the other user.
```Javascript
// EOS KEY2 - Decrypting the message
console.log("EOS User 2 decrypting the message\n");
let messageBuffer = Buffer.from(messageHex, 'hex');
let decryptedMessageBuffer = ecc.Aes.decrypt(eosPk2, eosPub1, nonce, messageBuffer, checksum);
let decryptedMessage = decryptedMessageBuffer.toString();
console.log("decrypted message: ", decryptedMessage);
console.log("message match?: ", (message == decryptedMessage));
//decrypted message:  Tacos via EOS
//message match?:  true
```
This takes care of generating the shared keys under the hood, so it let's us write less code. You can see or download the code [here](https://github.com/ajose01/eos_ecdh/blob/master/eosOnlyEncrypt.js).

## Conclusion
Learning the tools that are already available is super valuable. It opens up different options on dapp design, encryption and communications. I hope this was post was helpful 🙏

Angel Jose / @ajose01 - I poke at the blockchain with the [Sense team](https://makesense.com/), host [EOS meetups](https://www.meetup.com/EOS-Dapp-Development-Meetup/), learn and share about crypto and eat 🌮🌮.
* [sense.chat](https://sense.chat)
* [steemit](https://steemit.com/@ajose01/)
* [twitter](https://twitter.com/ajose01)
* [youtube](https://www.youtube.com/channel/UC3TaA9_obCreXZrhECmKs2Q)
* [past meetups](https://www.youtube.com/channel/UCN2TfO4zmz1PaezhBMtZXrw/videos)
* [github](https://github.com/ajose01)
