const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');
const scryptsy = require('scryptsy');
const sss = require('shamirs-secret-sharing');

const encrypt = {
    /**
     * Encrypt secret key
     * @param {Buffer} secretKey Secret key you want to encrypt.
     * @param {string} password Used for encryption. Required to remember.
     * @param {number} N A factor to control the overall CPU/Memory cost. Required to save.
     * @param {number} r A factor to control the blocksize for each mixing loop (memory usage). Required to save.
     * @param {number} p A factor to control the number of independent mixing loops (parallelism). Required to save.
     * @returns {{ salt: Buffer, nonce: Buffer, encryptedSeed: Buffer }}
     */
    secretKey: function (secretKey, password, N, r, p) {
        const salt = Buffer.from(nacl.randomBytes(32));
        const nonce = Buffer.from(nacl.randomBytes(24));
        const key = scryptsy(password, salt, N, r, p, 32);
        const keyPair = nacl.sign.keyPair.fromSecretKey(secretKey);
        const seed = keyPair.secretKey.slice(0, 32);
        const encryptedSeed = Buffer.from(nacl.secretbox(seed, nonce, key));
        return { salt, nonce, encryptedSeed }
    },
    /**
     * Divid salt and encrypt share
     * @param {Buffer} salt Parameters that was used at the time of secret key encryption
     * @param {Buffer} nonce Parameters that was used at the time of secret key encryption
     * @param {Buffer} secretKey Your secret key 
     * @param {Array<Buffer>} publicKeyList Collaborators public key list
     * @param {number} threshold Recoverable threshold
     * @returns {Array<{ signature: Buffer, encryptedShare: Buffer }>}
     */
    salt: function (salt, nonce, secretKey, publicKeyList, threshold) {
        const encryptedDataList = [];
        const shares = publicKeyList.length;
        if (0 < shares) {
            const shareList = sss.split(salt, { shares, threshold });
            for (let i = 0; i < shareList.length; i++) {
                const signature = Buffer.from(nacl.sign.detached(nacl.hash(shareList[i]), secretKey));
                const encryptedShare = Buffer.from(nacl.box(shareList[i], nonce, ed2curve.convertPublicKey(publicKeyList[i]), ed2curve.convertSecretKey(secretKey)));
                encryptedDataList.push({ signature, encryptedShare })
            }
        }
        return encryptedDataList
    }
}
const decrypt = {
    /**
     * Decrypt secret key
     * @param {string} password Parameters that was used at the time of secret key encryption
     * @param {Buffer} salt Parameters that was used at the time of secret key encryption
     * @param {Buffer} nonce Parameters that was used at the time of secret key encryption
     * @param {Buffer} encryptedSeed Encrypted seed value of secret key
     * @param {number} N Parameters that was used at the time of secret key encryption
     * @param {number} r Parameters that was used at the time of secret key encryption
     * @param {number} p Parameters that was used at the time of secret key encryption
     * @returns {Buffer|null}
     */
    secretKey: function (password, salt, nonce, encryptedSeed, N, r, p) {
        const key = scryptsy(password, salt, N, r, p, 32);
        const seed = nacl.secretbox.open(encryptedSeed, nonce, key)
        if (seed === null) {
            return null
        }
        return Buffer.from(nacl.sign.keyPair.fromSeed(seed).secretKey)
    },
    /**
     * Decrypt encrypted salt share
     * @param {Buffer} nonce Parameters that was used at the time of secret key encryption
     * @param {Buffer} encryptedShare Encrypted salt share
     * @param {Buffer} publicKey Collaborators public key
     * @param {Buffer} secretKey Secret key owner public key
     * @returns {Buffer|null}
     */
    share: function (nonce, encryptedShare, publicKey, secretKey) {
        const decryptedShare = nacl.box.open(encryptedShare, nonce, ed2curve.convertPublicKey(publicKey), ed2curve.convertSecretKey(secretKey));
        if (decryptedShare === null) {
            return null
        }
        return Buffer.from(decryptedShare)
    },
    /**
     * Combine salt share data
     * @param {Buffer} shareList salt share list
     * @returns {Buffer}
     */
    salt: function (shareList) {
        return sss.combine(shareList)
    }
}
/**
 * Verify decrypted share
 * @param {Buffer} share decrypted share
 * @param {Buffer} signature share hash signature data
 * @param {Buffer} publicKey used for signature
 * @returns {boolean}
 */
function verify(share, signature, publicKey) {
    return nacl.sign.detached.verify(nacl.hash(share), signature, publicKey)
}
module.exports = { encrypt, decrypt, verify }
