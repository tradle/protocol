
const typeforce = require('typeforce')
const traverse = require('traverse')
const {
  TYPE,
  SIG,
  SEQ,
  PREV_TO_RECIPIENT,
  PREVLINK,
  PERMALINK,
  PREVHEADER,
  AUTHOR,
  RECIPIENT,
  VERSION,
  TIMESTAMP,
  TYPES
} = require('@tradle/constants')

const { IDENTITY } = TYPES

const Errors = require('./errors')
const types = exports

types.merkleNode = typeforce.compile({
  hash: typeforce.Buffer,
  index: typeforce.Number
})

types.merkleLeaf = typeforce.compile({
  data: typeforce.Buffer,
  hash: typeforce.Buffer,
  index: typeforce.Number
})

types.merkleTree = typeforce.compile({
  nodes: typeforce.arrayOf(types.merkleNode),
  roots: typeforce.arrayOf(types.merkleNode)
})

// types.key = typeforce.oneOf(typeforce.String, typeforce.Object)

types.keyObj = function keyObj (val) {
  return val && (Buffer.isBuffer(val.pub) || Buffer.isBuffer(val.priv))
}

types.merkleRootOrObj = typeforce.oneOf(typeforce.Object, typeforce.Buffer)

// const OBJECT_TYPE = typeforce.compile({
//   header: typeforce.Object,
//   body: typeforce.Object
// })

// types.sigInput = typeforce.compile({
//   merkleRoot: typeforce.Buffer,
//   recipient: typeforce.Buffer
// })

// types.header = typeforce.compile({
//   sig: typeforce.Buffer,
//   sigKey: typeforce.Buffer,
//   sigInput: types.sigInput,
//   txId: typeforce.maybe(typeforce.String)
// })

types.ecPubKey = typeforce.compile({
  pub: typeforce.Buffer,
  curve: typeforce.String
})

types.ecPrivKey = typeforce.compile({
  priv: typeforce.Buffer,
  curve: typeforce.String
})

types.chainPubKey = function chainPubKey (key) {
  return Buffer.isBuffer(key.pub) && key.curve === 'secp256k1'
}

types.author = typeforce.compile({
  sigPubKey: types.ecPubKey,
  sign: typeforce.Function,
  permalink: typeforce.maybe(typeforce.String)
})

types.recipient = typeforce.compile({
  pubKey: types.ecPubKey,
  link: typeforce.String
})

// types.sig = typeforce.compile({
//   pubKey: types.ecPubKey,
//   sig: typeforce.Buffer
// })

types.object = ensureRequiredProps

// createObject input
types.createObjectInput = function createObjectInput (val) {
  types.ensureUnsigned(val)
  ensureRequiredPropsBase(val)
  return true
}

types.signObjectInput = function signObjectInput (val) {
  types.ensureUnsigned(val)
  ensureRequiredPropsPreSign(val)
  return true
}

types.rawObject = function rawObject (val) {
  types.ensureUnsigned(val)
  ensureVersionProps(val)
  ensureRequiredProps(val)
  return true
}

types.signedObject = function signedObject (val) {
  types.ensureSigned(val)
  ensureRequiredProps(val)
  ensureVersionProps(val)
  return true
}

types.linkOrObject = typeforce.oneOf(typeforce.String, types.signedObject)

types.messageBody = typeforce.compile({
  [RECIPIENT]: typeforce.String,
  // recipientPubKey: types.ecPubKey,
  object: types.signedObject,
  [SEQ]: typeforce.maybe(typeforce.Number),
  [PREV_TO_RECIPIENT]: typeforce.maybe(types.linkOrObject)
})

types.witness = typeforce.compile({
  a: typeforce.String,
  s: typeforce.String
})

types.ensureSigned = obj => {
  if (typeof obj[SIG] !== 'string') throw new Errors.InvalidProperty(SIG, 'expected signed object')
}

types.ensureUnsigned = obj => {
  if (typeof obj[SIG] !== 'undefined') throw new Errors.InvalidProperty(SIG, 'expected unsigned object')
}

types.ensureType = obj => {
  if (typeof obj[TYPE] !== 'string') throw new Errors.InvalidProperty(TYPE, `expected string ${TYPE}`)
}

types.ensureTimestamp = obj => {
  if (typeof obj[TIMESTAMP] !== 'number') throw new Errors.InvalidProperty(TIMESTAMP, `expected number ${TIMESTAMP}`)
}

types.ensureTimestampIncreased = (object, prev) => {
  return object._time > prev._time
}

types.ensureNonZeroVersion = object => {
  if (!(object[VERSION] > 0)) {
    throw new Errors.InvalidVersion(`expected non-zero version ${VERSION}`)
  }
}

function ensureVersionProps (obj) {
  // both or neither must be present
  let ok
  if (PERMALINK in obj) {
    ok = typeof obj[PERMALINK] === 'string' &&
      typeof obj[PREVLINK] === 'string' &&
      typeof obj[PREVHEADER] === 'string' &&
      obj[VERSION] > 0
  } else {
    ok = typeof obj[PREVLINK] === 'undefined' &&
      typeof obj[PREVHEADER] === 'undefined' &&
      (typeof obj[VERSION] === 'undefined' || obj[VERSION] === 0)
  }

  if (!ok) {
    throw new Errors.InvalidVersion(`expected either ${PERMALINK}, ${PREVLINK} and ${VERSION} > 0, or neither, and ${VERSION} === 0`)
  }
}

function findPathWithUndefinedVal (obj) {
  let bad
  traverse(obj).forEach(function (val) {
    if (val === undefined) {
      bad = this.path.join('.')
      this.update(undefined, true) // stop traversing
    }
  })

  return bad
}

// function ensureVersion (obj) {
//   if (typeof obj[VERSION] !== 'number') throw new Error(`expected number ${VERSION}`)
// }

function ensureAuthor (obj) {
  if (obj[TYPE] === IDENTITY && !obj[VERSION]) {
    if (obj[AUTHOR]) {
      throw new Errors.InvalidInput(`unexpected property ${AUTHOR}`)
    }
  } else {
    if (!obj[AUTHOR]) {
      throw new Errors.InvalidInput(`expected property ${AUTHOR}`)
    }
  }
}

function ensureRequiredProps (obj) {
  ensureRequiredPropsPreSign(obj)
  ensureAuthor(obj)
  return true
}

function ensureRequiredPropsPreSign (obj) {
  ensureRequiredPropsBase(obj)
  ensureVersionProps(obj)
  types.ensureTimestamp(obj)
  return true
}

function ensureRequiredPropsBase (obj) {
  types.ensureType(obj)
  const bad = findPathWithUndefinedVal(obj)
  if (bad) {
    throw new Errors.InvalidProperty(bad, 'must not have "undefined" values')
  }

  return true
}
