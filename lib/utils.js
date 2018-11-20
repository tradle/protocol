'use strict'

const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const EC = require('elliptic').ec
const typeforce = require('typeforce')
const stringify = require('json-stable-stringify')
const omit = require('lodash/omit')
const pick = require('lodash/pick')
const clone = require('lodash/clone')
const extend = require('lodash/extend')
const cloneDeep = require('lodash/cloneDeep')
const traverse = require('traverse')
// const nkey = require('nkey-ec')
const proto = require('./proto').schema
const types = require('./types')
const {
  SIG,
  TYPE,
  TIMESTAMP
} = require('./constants')
const noop = function () {}
const slice = Array.prototype.slice
const curves = {}
const utils = exports

exports.curve = function (name) {
  if (typeof name !== 'string') return name

  if (!curves[name]) {
    curves[name] = new EC(name)
  }

  return curves[name]
}

exports.assert = function (statement, msg) {
  if (!statement) throw new Error(msg || 'Assertion failed')
}

exports.asyncify = function asyncify (fn, allowMultipleCalls) {
  if (!fn) return noop
  if (fn._async) return fn

  let ticked
  let called
  let once = !allowMultipleCalls
  let ctx, args
  process.nextTick(function () {
    if (args) apply()
    else ticked = true
  })

  const asyncFn = function () {
    ctx = this
    args = arguments
    if (ticked) apply()
  }

  asyncFn._async = true
  return asyncFn

  function apply () {
    if (called && once) return

    called = true
    fn.apply(ctx, args)
  }
}

// TODO: use nkey
exports.sign = function sign (msg, key) {
  console.warn('utils.sign is deprecated, use nkey-{implementation} instead')
  typeforce(types.ecPrivKey, key)

  if (key.curve === 'secp256k1') {
    let sig = secp256k1.sign(msg, key.priv)

    // Ensure low S value
    sig = secp256k1.signatureNormalize(sig.signature)

    // Convert to DER array
    return secp256k1.signatureExport(sig)
  } else {
    return new Buffer(utils.curve(key.curve).sign(msg, key.priv).toDER())
  }
}

/**
 * extract key from signature, verifying sig
 */
exports.getSigKey = function getSigKey (msg, sig, verify) {
  console.warn('utils.getSigKey is deprecated')
  const parsed = utils.parseSig(sig)
  const key = parsed.pubKey
  sig = parsed.sig
  verify = verify || defaultVerify
  if (verify(key, msg, sig)) return key
}

function defaultVerify (key, msg, sig) {
  if (key.curve === 'secp256k1') {
    sig = secp256k1.signatureImport(sig)
    if (secp256k1.verify(msg, sig, key.pub)) {
      return key
    }
  } else {
    if (utils.curve(key.curve).verify(msg, sig, key.pub)) {
      return key
    }
    // else {
    //   console.log('nkey', nkey.fromJSON(key).verifySync(msg, sig))
    // }
  }
}

exports.publicKeyCombine = function (a, b) {
  if (Array.isArray(a)) {
    b = a[1]
    a = a[0]
  }

  if (a.curve !== b.curve) {
    throw new Error('curves do not match')
  }

  let val
  if (a.curve === 'secp256k1') {
    val = secp256k1.publicKeyCombine([a.pub, b.pub], false)
  } else {
    const curve = utils.curve(a.curve)
    a = curve.keyFromPublic(a)
    b = curve.keyFromPublic(b)
    val = new Buffer(a.pub.add(b.pub).encode('buffer'))
  }

  return {
    curve: a.curve,
    pub: val
  }
}

exports.ecPubKeysAreEqual = function (a, b) {
  return a.curve === b.curve && a.pub.equals(b.pub)
}

exports.omit = omit
exports.pick = pick
exports.clone = clone
exports.cloneDeep = cloneDeep
exports.extend = extend
exports.traverse = traverse

exports.sigToString = function (sig) {
  return typeof sig === 'string' ? sig : sig.toString('base64')
}

exports.sigToBuf = function (sig) {
  return Buffer.isBuffer(sig) ? sig : new Buffer(sig, 'base64')
}

exports.parseSig = function (sig) {
  return utils.decodeSig(sig)
}

exports.decodeSig = function (sig) {
  return proto.ECSignature.decode(utils.sigToBuf(sig))
}

exports.encodeSig = function (sig) {
  if (typeof sig.sig === 'string') sig.sig = new Buffer(sig.sig, 'hex')

  return proto.ECSignature.encode(sig)
}

/**
 * return a value synchronously or asynchronously
 * depending on if callback is passed
 * @param  {anything}   val [description]
 * @param  {?Function}  cb  [description]
 * @return {anything}   val
 */
exports.maybeAsync = function maybeAsync (val, cb) {
  if (cb) {
    process.nextTick(function () {
      cb(null, val)
    })
  }

  return val
}

exports.genECKey = function (curve) {
  curve = curve || 'secp256k1'
  let priv, pub
  if (curve === 'secp256k1') {
    do {
      priv = crypto.randomBytes(32)
    } while (!secp256k1.privateKeyVerify(priv))

    pub = secp256k1.publicKeyCreate(priv, false)
  } else {
    const pair = utils.curve(curve).genKeyPair()
    priv = pair.getPrivate().toBuffer()
    pub = new Buffer(pair.getPublic(false, 'buffer'))
  }

  return {
    priv: priv,
    pub: pub,
    curve: curve
  }
}
