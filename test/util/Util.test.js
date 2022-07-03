const { Util } = require('../../src/util')

describe('Util', () => {
  test('isPlainObject', async () => {
    expect(Util.isPlainObject({})).toBe(true)
    expect(Util.isPlainObject({ p1: 'hola', p2: 2 })).toBe(true)
    expect(Util.isPlainObject(1)).toBe(false)
    expect(Util.isPlainObject(Buffer.from('hola'))).toBe(false)
  })
})
