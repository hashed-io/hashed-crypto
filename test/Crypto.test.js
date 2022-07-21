global.File = class {}
const { Keyring } = require('@polkadot/keyring')
const { mnemonicGenerate } = require('@polkadot/util-crypto')
// const { stringToU8a, u8aToString } = require('@polkadot/util')
const { randomBytes } = require('tweetnacl')
const { Crypto } = require('../src')

let crypto = null

beforeAll(async () => {
  crypto = new Crypto()
})

describe('crypto', () => {
  test('cipher/decipher', async () => {
    const secret = await crypto.argon2id({ password: 'pass' })

    const privateKey = await crypto.deriveKey({ secret })
    let payload = { p1: 'hola', p2: 2 }
    let fullCipheredPayload = await crypto.cipher({ payload, privateKey })
    // console.log('encrypted: ', fullCipheredPayload)
    let decipheredPayload = await crypto.decipher({ fullCipheredPayload, privateKey })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(decipheredPayload).toEqual(payload)

    payload = randomBytes(16)
    fullCipheredPayload = await crypto.cipher({ payload, privateKey })
    // console.log('encrypted: ', fullCipheredPayload)
    decipheredPayload = await crypto.decipher({ fullCipheredPayload, privateKey })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(decipheredPayload).toEqual(payload)
  })

  test('cipher/decipher external nonce', async () => {
    const secret = await crypto.argon2id({ password: 'pass' })

    const privateKey = await crypto.deriveKey({ secret })
    const payload = { p1: 'hola', p2: 2 }
    const fullCipheredPayload = await crypto.cipher({ payload, privateKey, nonce: crypto.ownNonce() })
    // console.log('encrypted: ', fullCipheredPayload)
    const { cipheredPayload, nonce, type } = crypto.decodeOwnFullCipheredPayload(fullCipheredPayload)
    const decipheredPayload = await crypto.decipher({ cipheredPayload, nonce, privateKey, type })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(decipheredPayload).toEqual(payload)
  })

  test('cipher/decipher public/private key', async () => {
    const key1 = crypto.generateKeyPair()
    const { privateKey } = key1
    const payload = { p1: 'hola', p2: 2 }
    const fullCipheredPayload = await crypto.cipher({ payload, privateKey })
    // console.log('encrypted: ', fullCipheredPayload)
    const decipheredPayload = await crypto.decipher({ fullCipheredPayload, privateKey })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(decipheredPayload).toEqual(payload)
  })

  test('cipher/decipher shared', async () => {
    const key1 = crypto.generateKeyPair()
    const key2 = crypto.generateKeyPair()
    const payload = { p1: 'hola', p2: 2 }
    const fullCipheredPayload = await crypto.cipherShared({
      privateKey: key1.privateKey,
      publicKey: key2.publicKey,
      payload
    })
    // console.log('cipheredPayload: ', fullCipheredPayload)
    let decipheredPayload = crypto.decipherShared({
      privateKey: key1.privateKey,
      publicKey: key2.publicKey,
      fullCipheredPayload
    })
    expect(decipheredPayload).toEqual(payload)
    // console.log('decrypted1: ', decipheredPayload)
    decipheredPayload = crypto.decipherShared({
      privateKey: key2.privateKey,
      publicKey: key1.publicKey,
      fullCipheredPayload
    })
    expect(decipheredPayload).toEqual(payload)
    // console.log('decrypted2: ', decipheredPayload)
  })

  // test('cipher/decipher shared with substrate key', async () => {
  //   const key1 = crypto.generateKeyPair()
  //   const keyring = new Keyring()
  //   const substrateKey = keyring.addFromUri(mnemonicGenerate(), {}, 'ed25519')
  //   const key2 = {
  //     privateKey: Buffer.from(substrateKey.encodePkcs8()).toString('base64'),
  //     publicKey: Buffer.from(substrateKey.publicKey).toString('base64')
  //   }
  //   console.log('keys1: ', key1)
  //   console.log('privatekey: ', substrateKey.encodePkcs8())
  //   console.log('keys2: ', key2)
  //   const payload = { p1: 'hola', p2: 2 }
  //   const { fullCipheredPayload, type } = await crypto.cipherShared({
  //     privateKey: key1.privateKey,
  //     publicKey: key2.publicKey,
  //     payload
  //   })
  //   console.log('cipheredPayload: ', fullCipheredPayload)
  //   let decipheredPayload = crypto.decipherShared({
  //     privateKey: key1.privateKey,
  //     publicKey: key2.publicKey,
  //     fullCipheredPayload,
  //     type
  //   })
  //   expect(decipheredPayload).toEqual(payload)
  //   console.log('decrypted1: ', decipheredPayload)
  //   decipheredPayload = crypto.decipherShared({
  //     privateKey: key2.privateKey,
  //     publicKey: key1.publicKey,
  //     fullCipheredPayload,
  //     type
  //   })
  //   expect(decipheredPayload).toEqual(payload)
  //   console.log('decrypted2: ', decipheredPayload)
  // })

  test('cipher/decipher substrate', async () => {
    const keyring = new Keyring()
    const keypair = keyring.addFromUri(mnemonicGenerate(), {}, 'sr25519')
    const salt = crypto.salt()
    const password = keypair.sign(salt)
    // console.log('password: ', password)
    const secret = await crypto.argon2id({ password })

    const privateKey = await crypto.deriveKey({ secret })
    const payload = { p1: 'hola', p2: 2 }
    const fullCipheredPayload = await crypto.cipher({ payload, privateKey })
    // console.log('encrypted: ', fullCipheredPayload)
    const decipheredPayload = await crypto.decipher({ fullCipheredPayload, privateKey })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(decipheredPayload).toEqual(payload)
  })
})
