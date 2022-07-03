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

  generateKeyPair () {
    const {
      publicKey,
      secretKey
    } = box.keyPair()
    return {
      publicKey: Buffer.from(publicKey).toString('base64'),
      privateKey: Buffer.from(secretKey).toString('base64')
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
    privateKey
  }) {
    const key = this._decodeKey(privateKey)

    const nonce = randomBytes(secretbox.nonceLength)
    const {
      type,
      rawPayload
    } = await this._getRawPayload(payload)
    const cipheredPayload = secretbox(rawPayload, nonce, key)

    return {
      type,
      fullCipheredPayload: this._createFullCipheredPayload(cipheredPayload, nonce)
    }
  }

  decipher ({
    fullCipheredPayload,
    privateKey,
    type
  }) {
    const key = this._decodeKey(privateKey)
    const { cipheredPayload, nonce } = this._decodeFullCipheredPayload(fullCipheredPayload, secretbox.nonceLength)
    const payload = secretbox.open(cipheredPayload, nonce, key)

    if (!payload) {
      throw new Error('Could not decrypt message')
    }
    return this._toType(payload, type)
  }

  async cipherShared ({
    privateKey,
    publicKey,
    payload
  }) {
    const prvKey = this._decodeKey(privateKey)
    const pubKey = this._decodeKey(publicKey)

    const nonce = randomBytes(box.nonceLength)
    const {
      type,
      rawPayload
    } = await this._getRawPayload(payload)
    const cipheredPayload = box(rawPayload, nonce, pubKey, prvKey)
    return {
      type,
      fullCipheredPayload: this._createFullCipheredPayload(cipheredPayload, nonce)
    }
  };

  decipherShared ({
    privateKey,
    publicKey,
    fullCipheredPayload,
    type
  }) {
    const prvKey = this._decodeKey(privateKey)
    const pubKey = this._decodeKey(publicKey)
    const { cipheredPayload, nonce } = this._decodeFullCipheredPayload(fullCipheredPayload, box.nonceLength)
    const payload = box.open(cipheredPayload, nonce, pubKey, prvKey)
    if (!payload) {
      throw new Error('Could not decrypt message')
    }
    return this._toType(payload, type)
  }

  _toType (payload, type) {
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
    return Buffer.from(key, 'base64')
  }

  _encodeKey (rawKey) {
    return Buffer.from(rawKey).toString('base64')
  }

  _getExtension (extensionType) {
    return extensionType.indexOf('/') > -1 ? mime.extension(extensionType) : extensionType
  }

  _createFullCipheredPayload (cipheredPayload, nonce) {
    const fullPayload = new Uint8Array(nonce.length + cipheredPayload.length)
    fullPayload.set(nonce)
    fullPayload.set(cipheredPayload, nonce.length)

    return Buffer.from(fullPayload).toString('base64')
  }

  _decodeFullCipheredPayload (fullCipheredPayload, nonceLength) {
    const fullPayload = Buffer.from(fullCipheredPayload, 'base64')

    const nonce = fullPayload.subarray(0, nonceLength)
    const cipheredPayload = fullPayload.subarray(
      nonceLength,
      fullPayload.length
    )
    return {
      nonce,
      cipheredPayload
    }
  }

  async _getRawPayload (payload) {
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
