global.File = class {}
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
    let { fullCipheredPayload, type } = await crypto.cipher({ payload, privateKey })
    // console.log('encrypted: ', fullCipheredPayload)
    let decipheredPayload = await crypto.decipher({ fullCipheredPayload, privateKey, type })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(type).toEqual('json')
    expect(decipheredPayload).toEqual(payload)

    payload = randomBytes(16);
    ({ fullCipheredPayload, type } = await crypto.cipher({ payload, privateKey }))
    // console.log('encrypted: ', fullCipheredPayload)
    decipheredPayload = await crypto.decipher({ fullCipheredPayload, privateKey, type })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(type).toEqual('raw')
    expect(decipheredPayload).toEqual(payload)
  })

  test('cipher/decipher shared', async () => {
    const key1 = crypto.generateKeyPair()
    const key2 = crypto.generateKeyPair()
    const payload = { p1: 'hola', p2: 2 }
    const { fullCipheredPayload, type } = await crypto.cipherShared({
      privateKey: key1.privateKey,
      publicKey: key2.publicKey,
      payload
    })
    // console.log('cipheredPayload: ', fullCipheredPayload)
    let decipheredPayload = crypto.decipherShared({
      privateKey: key1.privateKey,
      publicKey: key2.publicKey,
      fullCipheredPayload,
      type
    })
    expect(decipheredPayload).toEqual(payload)
    // console.log('decrypted1: ', decipheredPayload)
    decipheredPayload = crypto.decipherShared({
      privateKey: key2.privateKey,
      publicKey: key1.publicKey,
      fullCipheredPayload,
      type
    })
    expect(decipheredPayload).toEqual(payload)
    // console.log('decrypted2: ', decipheredPayload)
  })
})
