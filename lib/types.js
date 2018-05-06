
const typeforce = require('typeforce')
const traverse = require('traverse')
const {
  TYPE,
  MESSAGE_TYPE,
  SIG,
  SEQ,
  PREV_TO_RECIPIENT,
  PREVLINK,
  PERMALINK,
  AUTHOR,
  VERSION,
  TYPES
} = require('@tradle/constants')

const { IDENTITY } = TYPES
const {
  HEADER_PROPS,
  REQUIRED_PROPS
} = require('./constants')

const types = exports

exports.merkleNode = typeforce.compile({
  hash: typeforce.Buffer,
  index: typeforce.Number
})

exports.merkleLeaf = typeforce.compile({
  data: typeforce.Buffer,
  hash: typeforce.Buffer,
  index: typeforce.Number
})

exports.merkleTree = typeforce.compile({
  nodes: typeforce.arrayOf(exports.merkleNode),
  roots: typeforce.arrayOf(exports.merkleNode)
})

// exports.key = typeforce.oneOf(typeforce.String, typeforce.Object)

exports.keyObj = function keyObj (val) {
  return val && (Buffer.isBuffer(val.pub) || Buffer.isBuffer(val.priv))
}

exports.merkleRootOrObj = typeforce.oneOf(typeforce.Object, typeforce.Buffer)

// const OBJECT_TYPE = typeforce.compile({
//   header: typeforce.Object,
//   body: typeforce.Object
// })

// exports.sigInput = typeforce.compile({
//   merkleRoot: typeforce.Buffer,
//   recipient: typeforce.Buffer
// })

// exports.header = typeforce.compile({
//   sig: typeforce.Buffer,
//   sigKey: typeforce.Buffer,
//   sigInput: exports.sigInput,
//   txId: typeforce.maybe(typeforce.String)
// })

exports.ecPubKey = typeforce.compile({
  pub: typeforce.Buffer,
  curve: typeforce.String
})

exports.ecPrivKey = typeforce.compile({
  priv: typeforce.Buffer,
  curve: typeforce.String
})

exports.chainPubKey = function chainPubKey (key) {
  return Buffer.isBuffer(key.pub) && key.curve === 'secp256k1'
}

exports.author = typeforce.compile({
  sigPubKey: exports.ecPubKey,
  sign: typeforce.Function
})

exports.recipient = typeforce.compile({
  pubKey: exports.ecPubKey,
  link: typeforce.String
})

// exports.sig = typeforce.compile({
//   pubKey: types.ecPubKey,
//   sig: typeforce.Buffer
// })

exports.object = ensureRequiredProps

exports.rawObject = function rawObject (val) {
  return typeof val[SIG] === 'undefined' &&
    ensureRequiredProps(val) &&
    // typeof val[NONCE] === 'string' &&
    isVersionedCorrectly(val)
}

exports.signedObject = function signedObject (val) {
  return typeof val[SIG] === 'string' && ensureRequiredProps(val) && isVersionedCorrectly(val)
}

exports.linkOrObject = typeforce.oneOf(typeforce.String, types.signedObject)

exports.messageBody = typeforce.compile({
  recipientPubKey: types.ecPubKey,
  object: types.signedObject,
  [SEQ]: typeforce.maybe(typeforce.Number),
  [PREV_TO_RECIPIENT]: typeforce.maybe(types.linkOrObject)
})

function isVersionedCorrectly (obj) {
  // both or neither must be present
  let ok
  if (PERMALINK in obj) {
    ok = typeof obj[PERMALINK] === 'string' && typeof obj[PREVLINK] === 'string'
  } else {
    ok = typeof obj[PREVLINK] === 'undefined'
  }

  if (!ok) {
    throw new Error(`expected either both ${PERMALINK}, ${PREVLINK}, or neither`)
  }

  return true
}

function hasUndefinedValues (obj) {
  var failed
  traverse(obj).forEach(function (val) {
    if (val === undefined) {
      failed = true
      this.update(undefined, true) // stop traversing
    }
  })

  return failed
}

function ensureRequiredProps (obj) {
  if (typeof obj[TYPE] !== 'string') throw new Error(`expected string ${TYPE}`)
  if (typeof obj[VERSION] !== 'number') throw new Error(`expected number ${VERSION}`)
  if (obj[TYPE] === IDENTITY) {
    if (obj[AUTHOR]) {
      throw new Error(`unexpected property ${AUTHOR}`)
    }
  } else {
    if (!obj[AUTHOR]) {
      throw new Error(`expected property ${AUTHOR}`)
    }
  }

  if (hasUndefinedValues(obj)) throw new Error('must not have "undefined" values')
  return true
}
