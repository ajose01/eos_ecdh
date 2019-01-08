# Encrypting EOS communication via ECC / ECDH
_Disclaimer: I'm sharing as I'm learning... please use at your own risk, or better yet share in comments how to improve! Also, I will use terms as seed / password loosely, to illustrate the process._

Can we encrypt communication between two EOS users using the private / public keys already in our possession? YES! Well... with some caveats. ECC in itself is not an encryption algorithm. In EOS and other blockchains it is used to sign transactions, but not to obscure what is being signed. However, it can be leveraged to encrypt communications if we take a couple steps.

## Step 1 - Generate a shared encryption seed.

In order to encrypt our communications, we would usually need an encryption seed (for us encryption noobs, think something like a password) that we use to secure our communication. As long as both parties know the password, we can decrypt our message. The trick is having a common seed / pass that we never have to communicate to the other party. In crypto world, we already have enough keys to worry about! How can we accomplish this?

Enter [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman). 
