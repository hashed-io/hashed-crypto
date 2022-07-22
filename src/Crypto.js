const mime = require('mime-types')
const { argon2id } = require('hash-wasm')
const hkdf = require('js-crypto-hkdf')
const { v4: uuidv4 } = require('uuid')
const { box, secretbox, randomBytes } = require('tweetnacl')

class Crypto {
  constructor ({
    parallelism = 1,
    iterations = 256,
    memorySize = 512
  } = {}) {
    this.parallelism = parallelism
    this.iterations = iterations
    this.memorySize = memorySize
  }

  salt () {
    return randomBytes(16)
  }

  ownNonce () {
    return randomBytes(secretbox.nonceLength)
  }

  sharedNonce () {
    return randomBytes(box.nonceLength)
  }

  generateKeyPair () {
    const {
      publicKey,
      secretKey
    } = box.keyPair()
    return {
      publicKey: this._encodeKey(publicKey),
      privateKey: this._encodeKey(secretKey)
    }
  }

  async argon2id ({ password, salt, hashLength = 32 }) {
    if (!salt) {
      salt = this.salt()
    }

    const key = await argon2id({
      password,
      salt, // salt is a buffer containing random bytes
      parallelism: this.parallelism,
      iterations: this.iterations,
      memorySize: this.memorySize, // use 512KB memory
      hashLength, // output size = 32 bytes
      outputType: 'binary' // return standard encoded string containing parameters needed to verify the key
    })
    return key
  }

  async deriveKey ({ secret, salt, keyLength = 32 }) {
    const info = '' // information specified in rfc5869
    if (!salt) {
      salt = this.salt()
    }

    const { key } = await hkdf.compute(secret, 'SHA-256', keyLength, info, salt)
    return this._encodeKey(key)
  }

  async cipher ({
    payload,
    privateKey,
    nonce = null,
    type = null // If passing a raw payload, this parameter would be set as type
  }) {
    const key = this._decodeKey(privateKey)

    nonce = nonce || this.ownNonce()
    const {
      type: actualType,
      rawPayload
    } = await this.getRawPayload(payload)
    type = actualType === 'raw' && type ? type : actualType
    const cipheredPayload = secretbox(rawPayload, nonce, key)

    return this._createFullCipheredPayload(cipheredPayload, nonce, type)
  }

  /**
   * deciphers a payload, either the fullCipheredPayload or cipheredPayload and nonce must be
   * specified
   *
   * @param {string} [fullCipheredPayload] base64 encoded ciphered payload including nonce
   * @param {Buffer} [cipheredPayload] ciphered payload
   * @param {Buffer} [nonce]
   * @param {string} privateKey base64 encoded private key
   * @param {string} type type of the payload
   * @returns
   */
  decipher ({
    fullCipheredPayload = null,
    cipheredPayload = null,
    nonce = null,
    privateKey,
    type = 'raw'
  }) {
    const key = this._decodeKey(privateKey)
    if (fullCipheredPayload) {
      ({ cipheredPayload, nonce, type } = this.decodeOwnFullCipheredPayload(fullCipheredPayload))
    }
    const payload = secretbox.open(cipheredPayload, nonce, key)

    if (!payload) {
      throw new Error('Could not decrypt message')
    }
    return this.toType(payload, type)
  }

  async cipherShared ({
    privateKey,
    publicKey,
    payload
  }) {
    const prvKey = this._decodeKey(privateKey)
    const pubKey = this._decodeKey(publicKey)

    const nonce = this.sharedNonce()
    const {
      type,
      rawPayload
    } = await this.getRawPayload(payload)
    const cipheredPayload = box(rawPayload, nonce, pubKey, prvKey)
    return this._createFullCipheredPayload(cipheredPayload, nonce, type)
  };

  decipherShared ({
    privateKey,
    publicKey,
    fullCipheredPayload
  }) {
    const prvKey = this._decodeKey(privateKey)
    const pubKey = this._decodeKey(publicKey)
    const { cipheredPayload, nonce, type } = this.decodeSharedFullCipheredPayload(fullCipheredPayload)
    const payload = box.open(cipheredPayload, nonce, pubKey, prvKey)
    if (!payload) {
      throw new Error('Could not decrypt message')
    }
    return this.toType(payload, type)
  }

  toType (payload, type) {
    if (type === 'raw') {
      return payload
    } else if (type === 'json') {
      return JSON.parse(Buffer.from(payload).toString('utf8'))
    } else {
      payload = new Uint8Array(payload)
      return new File([payload], `payload-${uuidv4()}.${type}`, { type: mime.lookup(type) })
    }
  }

  _decodeKey (key) {
    if (key.startsWith('0x')) {
      key = key.substring(2)
    }
    return Buffer.from(key, 'hex')
  }

  _encodeKey (rawKey) {
    return `0x${Buffer.from(rawKey).toString('hex')}`
  }

  _getExtension (extensionType) {
    return extensionType.indexOf('/') > -1 ? mime.extension(extensionType) : extensionType
  }

  _createFullCipheredPayload (cipheredPayload, nonce, type) {
    let fullPayload = new Uint8Array(nonce.length + cipheredPayload.length)
    fullPayload.set(nonce)
    fullPayload.set(cipheredPayload, nonce.length)
    fullPayload = Buffer.from(fullPayload).toString('base64')
    if (type !== 'raw') {
      fullPayload = `${fullPayload}#${type}`
    }
    return fullPayload
  }

  decodeFullCipheredPayload (fullCipheredPayload, nonceLength) {
    let [fullPayload, type] = fullCipheredPayload.split('#')
    type = type || 'raw'
    fullPayload = Buffer.from(fullPayload, 'base64')

    const nonce = fullPayload.subarray(0, nonceLength)
    const cipheredPayload = fullPayload.subarray(
      nonceLength,
      fullPayload.length
    )
    return {
      nonce,
      cipheredPayload,
      type
    }
  }

  decodeOwnFullCipheredPayload (fullCipheredPayload) {
    return this.decodeFullCipheredPayload(fullCipheredPayload, secretbox.nonceLength)
  }

  decodeSharedFullCipheredPayload (fullCipheredPayload) {
    return this.decodeFullCipheredPayload(fullCipheredPayload, box.nonceLength)
  }

  async getRawPayload (payload) {
    let type = null
    let rawPayload = null
    if (payload instanceof Buffer || payload instanceof Uint8Array) {
      type = 'raw'
      rawPayload = payload
    } else if (payload instanceof File) {
      type = this._getExtension(payload.type)
      rawPayload = new Uint8Array(await payload.arrayBuffer())
    } else {
      type = 'json'
      rawPayload = Buffer.from(JSON.stringify(payload), 'utf8')
    }
    return { type, rawPayload }
  }
}

module.exports = Crypto
