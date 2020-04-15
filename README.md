# Distributed Key Encryption

Encrypt private key with password and random salt. Random salt is divided according to the secret sharing method. The split data can be deposited with family, custodian, or any other trusted third parties.

## Installation

Using npm in your project

```
npm install @kunroku/dicrypt
```

## CDN

```
<script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@kunroku/iost@1.0.0/dist/dicrypt.min.js"></script>
```

exports to window.IOST global.


## API

##### dicrypt.encrypt.secretKey(secretKey, password, N, r, p)

Encrypt secret key.

- secretKey: Secret key you want to encrypt.
- password: Used for encryption. Required to remember.
- N: A factor to control the overall CPU/Memory cost. Required to save.
- r: A factor to control the blocksize for each mixing loop (memory usage). Required to save.
- p: A factor to control the number of independent mixing loops (parallelism). Required to save.

This api returns: { salt: Buffer, nonce: Buffer, encryptedSeed: Buffer }

##### dicrypt.encrypt.salt(salt, nonce, secretKey, publicKeyList, threshold)

Divid salt and encrypt share

- salt: Parameters that was used at the time of secret key encryption
- nonce: Parameters that was used at the time of secret key encryption
- secretKey: Your secret key 
- publicKeyList: Collaborators public key list
- threshold: Recoverable threshold


This api returns: Array<{ signature: Buffer, encryptedShare: Buffer }>

##### dicrypt.decrypt.secretKey(password, salt, nonce, encryptedSeed, N, r, p)

Decrypt secret key

- password: Parameters that was used at the time of secret key encryption
- salt: Parameters that was used at the time of secret key encryption
- nonce: Parameters that was used at the time of secret key encryption
- encryptedSeed: Encrypted seed value of secret key
- N: Parameters that was used at the time of secret key encryption
- r: Parameters that was used at the time of secret key encryption
- p: Parameters that was used at the time of secret key encryption

this api returns: Buffer or null

##### dicrypt.decrypt.share(nonce, encryptedShare, publicKey, secretKey)

Decrypt encrypted salt share

- nonce: Parameters that was used at the time of secret key encryption
- encryptedShare: Encrypted salt share
- publicKey: Collaborators public key
- secretKey: Secret key owner public key

This api returns: Buffer or null

##### dicrypt.decrypt.salt(sharList)

Combine salt share data

- shareList: salt share list

##### dicrypt.verify(share, signature, publicKey)

Verify decrypted share

- share: decrypted share
- signature: share hash signature data
- publicKey: used for signature

This api returns: boolean