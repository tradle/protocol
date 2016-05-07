
'use strict'

const ec = require('secp256k1')
const proto = require('./proto')

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

exports.verify = function verify (msg, sig, key) {
  try {
    const parsed = proto.schema.Signature.decode(sig)
    key = parsed.sigPubKey.value
    sig = parsed.sig
  } catch (err) {
  }

  sig = ec.signatureImport(sig)
  return ec.verify(msg, sig, key)
}

exports.omit = function omit (obj) {
  let copy = {}
  let omitted = Array.prototype.slice.call(arguments, 1)
  for (let p in obj) {
    if (omitted.indexOf(p) === -1) {
      copy[p] = obj[p]
    }
  }

  return copy
}

exports.pick = function pick (obj) {
  let copy = {}
  var i = arguments.length
  while (i-- > 1) {
    var p = arguments[i]
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
