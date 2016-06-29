
const typeforce = require('typeforce')
const constants = require('./constants')
const TYPE = constants.TYPE
const MESSAGE_TYPE = constants.MESSAGE_TYPE
const SIG = constants.SIG
const SEQ = constants.SEQ
const PREV_TO_SENDER = constants.PREV_TO_SENDER
const PREVLINK = constants.PREVLINK
const PERMALINK = constants.PERMALINK
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
  return pub && (Buffer.isBuffer(val.pub) || Buffer.isBuffer(val.priv))
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

exports.object = typeforce.compile({
  [TYPE]: typeforce.String
})

exports.rawObject = function rawObject (val) {
  return typeof val[SIG] === 'undefined' &&
  typeof val[TYPE] === 'string' &&
  // typeof val[NONCE] === 'string' &&
  isVersionedCorrectly(val)
}

exports.signedObject = function signedObject (val) {
  return typeof val[SIG] === 'string' && typeof val[TYPE] === 'string' && isVersionedCorrectly(val)
}

exports.linkOrObject = typeforce.oneOf(typeforce.String, types.signedObject)

exports.messageBody = typeforce.compile({
  recipientPubKey: types.ecPubKey,
  object: types.signedObject,
  [SEQ]: typeforce.maybe(typeforce.Number),
  [PREV_TO_SENDER]: typeforce.maybe(types.linkOrObject)
})

function isVersionedCorrectly (obj) {
  // both or neither must be present
  if (PERMALINK in obj) {
    return typeof obj[PERMALINK] === 'string' && typeof obj[PREVLINK] === 'string'
  }

  return typeof obj[PREVLINK] === 'undefined'

  // return !!obj[PERMALINK] === !!obj[PREVLINK]
}
