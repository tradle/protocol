
'use strict'

const ec = require('secp256k1')

exports.assert = function (statement, msg) {
  if (!statement) throw new Error(msg || 'Assertion failed')
}

exports.asyncify = function asyncify (fn, allowMultipleCalls) {
  if (fn._async) return fn

  let sync
  let called
  let once = !allowMultipleCalls
  let ctx, args
  process.nextTick(function () {
    if (args) apply()
    else sync = true
  })

  const asyncFn = function () {
    ctx = this
    args = arguments
    if (sync) apply()
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

