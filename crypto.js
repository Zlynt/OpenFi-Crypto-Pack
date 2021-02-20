const runningUnderNode = (typeof window === 'undefined') && (typeof process === 'object');

let crypto = {};


if (runningUnderNode) {
    const { subtle } = require('crypto').webcrypto;
    const { sign } = require('crypto');
    crypto.subtle = subtle;
    crypto.sign = sign;
}

const cryptoModule = {
    base64: {
        JSON: {
            encode: (message) => {
                if (runningUnderNode)
                    return Buffer.from(JSON.stringify(message)).toString('base64');
                else
                    return btoa(JSON.stringify(message));

            },
            decode: (message) => {
                if (runningUnderNode)
                    return JSON.parse(Buffer.from(message, 'base64').toString());
                else
                    return JSON.parse(atob(message));
            }
        },
        Uint8Array: {
            encode: (message) => {
                if (runningUnderNode) {
                    //Encoding
                    let encoded = JSON.stringify(message);

                    encoded = Buffer.from(encoded).toString('base64');

                    return encoded;
                } else {
                    //Encoding
                    let encoded = JSON.stringify(message);

                    encoded = btoa(encoded);
                    return encoded;
                }
            },
            decode: (message) => {
                if (runningUnderNode) {

                    let decoded = Buffer.from(message, 'base64').toString();
                    decoded = JSON.parse(decoded);
                    let decoded_tmp = [];
                    Object.keys(decoded).forEach((key) => {
                        decoded_tmp.push(decoded[key]);
                    });
                    decoded = new Uint8Array(decoded_tmp);
                    return decoded;
                } else {
                    //Decoding
                    let decoded = atob(message);

                    decoded = JSON.parse(decoded);

                    let decoded_tmp = [];
                    Object.keys(decoded).forEach((key) => {
                        decoded_tmp.push(decoded[key]);
                    });
                    decoded = new Uint8Array(decoded_tmp);

                    return decoded;
                }
            }
        }
    },
    ecdsa: {
        generateKeyPair: async () => {
            if (runningUnderNode) {
                const { publicKey, privateKey } = await crypto.subtle.generateKey({
                    name: 'ECDSA',
                    namedCurve: "P-521",
                }, true, ['sign', 'verify']);

                return {
                    publicKey: cryptoModule.base64.JSON.encode(await crypto.subtle.exportKey('jwk', publicKey)),
                    privateKey: cryptoModule.base64.JSON.encode(await crypto.subtle.exportKey('jwk', privateKey))
                };
            } else {
                let keys = await window.crypto.subtle.generateKey(
                    {
                        name: "ECDSA",
                        namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                    },
                    true, //whether the key is extractable (i.e. can be used in exportKey)
                    ["sign", "verify"] //can be any combination of "sign" and "verify"
                );
                return {
                    publicKey: cryptoModule.base64.JSON.encode(await window.crypto.subtle.exportKey(
                        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                        keys.publicKey //can be a publicKey or privateKey, as long as extractable was true
                    )),
                    privateKey: cryptoModule.base64.JSON.encode(await window.crypto.subtle.exportKey(
                        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                        keys.privateKey //can be a publicKey or privateKey, as long as extractable was true
                    )),
                };
            }
        },
        sign: async (privateKey, data) => {
            const textEncoder = new TextEncoder();

            let unpackedPrivateKey = cryptoModule.base64.JSON.decode(privateKey);
            let unpackedData = textEncoder.encode(data);

            let key;

            if (runningUnderNode) {
                key = await crypto.subtle.importKey(
                    'jwk',
                    unpackedPrivateKey,
                    {
                        name: "ECDSA",
                        namedCurve: unpackedPrivateKey.crv,
                    },
                    false,
                    ['sign']
                );
            } else {
                key = await window.crypto.subtle.importKey(
                    "jwk",
                    unpackedPrivateKey,
                    {
                        name: "ECDSA",
                        namedCurve: unpackedPrivateKey.crv,
                    },
                    false,
                    ["sign"]
                );
            }

            let signature;

            if (runningUnderNode) {
                signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-512' }, key, unpackedData));
            } else {
                signature = new Uint8Array(await window.crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-512" } }, key, unpackedData));
            }

            return cryptoModule.base64.Uint8Array.encode(signature);
        },
        verify: async (publicKey, signature, data) => {
            const textEncoder = new TextEncoder();

            let unpackedPublicKey = cryptoModule.base64.JSON.decode(publicKey);
            let unpackedSignature = cryptoModule.base64.Uint8Array.decode(signature);
            let unpackedData = textEncoder.encode(data);

            let key;

            if (runningUnderNode) {
                key = await crypto.subtle.importKey(
                    'jwk',
                    unpackedPublicKey,
                    {
                        name: "ECDSA",
                        namedCurve: "P-521",
                    },
                    false,
                    ['verify']
                );
            } else {
                key = await window.crypto.subtle.importKey(
                    "jwk",
                    unpackedPublicKey,
                    {
                        name: "ECDSA",
                        namedCurve: unpackedPublicKey.crv,
                    },
                    false,
                    ["verify"]
                );
            }

            if (runningUnderNode) {
                return await crypto.subtle.verify(
                    {
                        name: 'ECDSA',
                        hash: 'SHA-512'
                    },
                    key,
                    unpackedSignature,
                    unpackedData
                );
            } else {
                return await window.crypto.subtle.verify(
                    {
                        name: "ECDSA",
                        hash: {
                            name: "SHA-512"
                        },
                    },
                    key,
                    unpackedSignature,
                    unpackedData
                );
            }
        }
    },
    ntru: {
        generateKeyPair: async () => {
            if (!runningUnderNode) {
                let keys = await ntru.keyPair();
                return {
                    privateKey: cryptoModule.base64.Uint8Array.encode(keys.privateKey),
                    publicKey: cryptoModule.base64.Uint8Array.encode(keys.publicKey)
                }
            }
        },
        encrypt: async (publicKey, Uint8ArrayData) => {
            if (!runningUnderNode) {
                let key = cryptoModule.base64.Uint8Array.decode(publicKey);

                return cryptoModule.base64.Uint8Array.encode(await ntru.encrypt(Uint8ArrayData, key));
            }
        },
        decrypt: async (privateKey, Uint8ArrayEncryptedData) => {
            if (!runningUnderNode) {
                let key = cryptoModule.base64.Uint8Array.decode(privateKey);

                let data = cryptoModule.base64.Uint8Array.decode(Uint8ArrayEncryptedData);

                return await ntru.decrypt(data, key);
            }
        }
    },
    aes: {
        encrypt: (password, text) => {
            return CryptoJS.AES.encrypt(text, password).toString();
        },
        decrypt: (password, encryptedData) => {
            return CryptoJS.AES.decrypt(encryptedData, password).toString(CryptoJS.enc.Utf8);
        }
    },
    sha512: async (message) => {
        if (runningUnderNode) {
            return crypto.createHash('sha512').update(message).digest('hex');
        } else {
            const hash = await window.crypto.subtle.digest('SHA-512', new TextEncoder().encode(message));
            const hashArray = Array.from(new Uint8Array(hash));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hashHex;
        }
    }
}


if (runningUnderNode) {
    module.exports = cryptoModule;
}