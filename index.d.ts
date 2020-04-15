// Type definitions for dicrypt.js

export as namespace dicrypt;

declare const dicrypt: dicrypt;

export = dicrypt;

declare namespace dicrypt {
    export interface encrypt {
        secretKey(secretKey: Buffer, password: string, N: number, r: number, p: number): { salt: Buffer, nonce: Buffer, encryptedSeed: Buffer }
        salt(salt: Buffer, nonce: Buffer, secretKey: Buffer, publicKeyList: Array<Buffer>, threshold: number): Array<{ signature: Buffer, encryptedShare: Buffer }>    
    }
    export interface decrypt {
        secretKey(password: string, salt: Buffer, nonce: Buffer, encryptedSeed: Buffer, N: number, r: number, p: number): Buffer | null
        share(nonce: Buffer, encryptedShare: Buffer, publicKey: Buffer, secretKey: Buffer): Buffer
        salt(shareList: Array<Buffer>): Buffer
    }
    export interface verify {
        (share: Buffer, signature: Buffer, publicKey: Buffer): boolean
    }
}

declare interface dicrypt {
    encrypt: dicrypt.encrypt
    decrypt: dicrypt.decrypt
    verify: dicrypt.verify
}