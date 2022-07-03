class Util {
  static isPlainObject (o) {
    return o.constructor && o.constructor.name === 'Object'
  }
}

module.exports = Util
