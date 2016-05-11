
'use strict'

const ec = require('secp256k1')
const proto = require('./proto')
const slice = Array.prototype.slice

exports.assert = function (statement, msg) {
  if (!statement) throw new Error(msg || 'Assertion failed')
}

exports.asyncify = function asyncify (fn, allowMultipleCalls) {
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

exports.sign = function sign (msg, key) {
  let sig = ec.sign(msg, key)

  // Ensure low S value
  sig = ec.signatureNormalize(sig.signature)

  // Convert to DER array
  return ec.signatureExport(sig)
}

exports.getSigKey = function getSigKey (msg, sig, key) {
  let parsed
  try {
    parsed = proto.schema.Signature.decode(sig)
    key = parsed.sigPubKey.value
    sig = parsed.sig
  } catch (err) {
  }

  sig = ec.signatureImport(sig)
  if (ec.verify(msg, sig, key)) {
    return parsed ? parsed.sigPubKey : key
  }
}

exports.omit = function omit (obj) {
  const props = Array.isArray(arguments[1]) ? arguments[1] : slice.call(arguments, 1)
  let copy = {}
  // let omitted = slice.call(arguments, 1)
  for (let p in obj) {
    if (props.indexOf(p) === -1) {
      copy[p] = obj[p]
    }
  }

  return copy
}

exports.pick = function pick (obj) {
  const props = Array.isArray(arguments[1]) ? arguments[1] : slice.call(arguments, 1)
  let copy = {}
  let i = props.length
  while (i--) {
    let p = props[i]
    copy[p] = obj[p]
  }

  return copy
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
