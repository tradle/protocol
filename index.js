
'use strict'

const crypto = require('crypto')
const clone = require('xtend')
const extend = require('xtend/mutable')
const typeforce = require('typeforce')
const stringify = require('json-stable-stringify')
const merkleProofs = require('merkle-proofs')
const merkleGenerator = require('merkle-tree-stream/generator')
const secp256k1 = require('secp256k1')
const flatTree = require('flat-tree')
const constants = require('@tradle/constants')
const proto = require('./lib/proto')
const utils = require('./lib/utils')
const types = require('./lib/types')
const CURVE = 'secp256k1'
const {
  SIG,
  SEQ,
  TYPE,
  PREVLINK,
  PERMALINK,
  VERSION,
  AUTHOR,
  PREVHEADER,
} = constants

const { HEADER_PROPS } = require('./lib/constants')
const ENC = 'hex'
const sha256 = (data, enc) => {
  return crypto.createHash('sha256').update(data).digest(enc)
}

const concatSha256 = (a, b, enc) => {
  return crypto.createHash('sha256').update(a).update(b).digest(enc)
}

const getHeaderHash = object => hashHeader(getHeader(object))

const getMerkleRoot = (tree) => {
  return tree.roots[0].hash
}

const computeMerkleRoot = (obj, opts) => {
  const tree = createMerkleTree(obj, getMerkleOpts(opts))
  return getMerkleRoot(tree)
}

const headerHashFn = obj => computeMerkleRoot(obj).toString(ENC)

const toMerkleRoot = (merkleRootOrObj, opts) => {
  return Buffer.isBuffer(merkleRootOrObj)
    ? merkleRootOrObj
    : computeMerkleRoot(getBody(merkleRootOrObj), opts)
}

const createObject = (opts) => {
  typeforce({
    object: types.rawObject,
    prev: typeforce.maybe(types.signedObject),
    orig: typeforce.maybe(types.merkleRootOrObj)
  }, opts, true)

  // shallow copy not too safe
  const obj = getBody(opts.object)
  if (opts.prev) {
    obj[PREVLINK] = getStringLink(opts.prev)
  }

  if (opts.orig) {
    obj[PERMALINK] = getStringLink(opts.orig)
  }

  if (obj[PREVLINK] || obj[PERMALINK]) {
    obj[VERSION] = (obj[VERSION] || 0) + 1
  } else {
    obj[VERSION] = 0
  }

  return obj
}

const nextVersion = (object, link) => {
  link = link || getStringLink(object)
  object = clone(object)
  HEADER_PROPS.forEach(prop => {
    delete object[prop]
  })

  // delete object[SIG]
  object[PREVLINK] = link
  object[PERMALINK] = object[PERMALINK] || link
  object[VERSION] = (object[VERSION] || 0) + 1
  return object
}

const merkleAndSign = (opts, cb) => {
  typeforce({
    author: types.author,
    object: types.rawObject
  }, opts)

  const author = opts.author
  const object = opts.object
  if (object[SIG]) throw new Error('object is already signed')

  const tree = createMerkleTree(getBody(object), getMerkleOpts(opts))
  const merkleRoot = getMerkleRoot(tree)
  author.sign(merkleRoot, function (err, sig) {
    if (err) return cb(err)

    const encodedSig = utils.encodeSig({
      pubKey: author.sigPubKey,
      sig: sig
    })

    sig = utils.sigToString(encodedSig)
    const signed = extend({ [SIG]: sig }, object)

    cb(null, {
      tree: tree,
      merkleRoot: merkleRoot,
      sig: sig,
      object: signed
    })
  })
}

/**
 * calculate a public key that seals `link` based on `basePubKey`
 */
const calcSealPubKey = (opts) => {
  typeforce({
    basePubKey: types.chainPubKey,
    object: typeforce.maybe(typeforce.Object),
    headerHash: typeforce.maybe(typeforce.String)
  }, opts)

  let { basePubKey, object, headerHash } = opts
  if (!headerHash) headerHash = hashHeader(getHeader(object))

  return utils.publicKeyCombine([
    basePubKey,
    pubKeyFromHeaderHash(headerHash)
  ])
}

const calcSealPrevPubKey = (opts) => {
  typeforce({
    basePubKey: types.chainPubKey,
    object: typeforce.maybe(typeforce.Object),
    prevHeaderHash: typeforce.maybe(typeforce.String)
  }, opts)

  let { basePubKey, object, prevHeaderHash } = opts
  if (object) {
    prevHeaderHash = object[PREVHEADER]
    if (!prevHeaderHash) {
      throw new Error(`expected object.${PREVHEADER}`)
    }
  } else if (!prevHeaderHash) {
    throw new Error(`expected "object" or "prevHeaderHash"`)
  }

  return utils.publicKeyCombine([
    basePubKey,
    prevPubKeyFromHeaderHash(prevHeaderHash)
  ])
}

const verifySealPubKey = (opts) => {
  typeforce({
    object: typeforce.Object,
    basePubKey: types.chainPubKey,
    sealPubKey: types.chainPubKey
  }, opts)

  const object = opts.object
  if (!object[SIG]) throw new Error('object must be signed')

  const expected = utils.publicKeyCombine([
    opts.basePubKey,
    pubKeyFromObject(object)
  ])

  return utils.ecPubKeysAreEqual(expected, opts.sealPubKey)
}

const verifySealPrevPubKey = (opts) => {
  typeforce({
    sealPrevPubKey: types.chainPubKey
  }, opts)

  const expected = calcSealPrevPubKey(opts)
  return utils.ecPubKeysAreEqual(expected, opts.sealPrevPubKey)
}

const parseObject = (opts) => {
  const object = opts.object
  const body = getBody(object)
  const parsedSig = utils.parseSig(object[SIG])
  return {
    merkleRoot: computeMerkleRoot(body, getMerkleOpts(opts)),
    body: body,
    sig: parsedSig.sig,
    pubKey: parsedSig.pubKey
  }
}

const getSigKey = (opts) => {
  typeforce({
    object: typeforce.Object,
    verify: typeforce.maybe(typeforce.Function)
  }, opts)

  const object = opts.object
  // necessary step to make sure key encoded
  // in signature is that key used to sign
  const merkleRoot = computeMerkleRoot(getBody(object), getMerkleOpts(opts))
  const body = getBody(object)
  return utils.getSigKey(merkleRoot, object[SIG], opts.verify)
}

const verifySig = (opts) => {
  try {
    return !!getSigKey(opts)
  } catch (err) {
    return false
  }
}

const ensurePrevHeader = object => {
  if (object[PREVLINK] && !object[PREVHEADER]) {
    throw new Error(`expected object to have ${PREVHEADER}`)
  }
}

/**
 * validate object sequence
 * @param  {[type]} object     [description]
 * @param  {[type]} prev       [description]
 * @param  {[type]} merkleOpts [description]
 * @return {[type]}            [description]
 */
const validateVersioning = (opts) => {
  const { object, orig, prev } = opts
  if (typeof object[VERSION] !== 'number') {
    throw new Error(`missing ${VERSION}`)
  }

  const validatePrev = object[PREVLINK] || object[VERSION] !== 0 || prev
  const validateOrig = object[PERMALINK] || object[VERSION] !== 0 || orig
  if (validatePrev || validateOrig) {
    ensureNonZeroVersion(object)
    ensurePrevHeader(object)
  } else {
    if (object[VERSION] && object[VERSION] !== 0) {
      throw new Error(`expected object.${VERSION} to be 0`)
    }
  }

  if (validatePrev) {
    if (!object[PREVLINK]) throw new Error(`expected object.${PREVLINK}`)
    if (!prev) throw new Error('expected "prev"')
    if (object[PREVLINK] !== getStringLink(prev)) {
      throw new Error(`object.${PREVLINK} and "prev" don't match`)
    }

    if (object[PREVHEADER] !== getHeaderHash(prev)) {
      throw new Error(`expected object.${PREVHEADER} to equal the header hash of "prev"`)
    }
  }

  if (validateOrig) {
    if (!object[PERMALINK]) throw new Error(`expected object.${PERMALINK}`)

    if (object[PERMALINK] && !orig) {
      throw new Error('expected "orig"')
    }

    if (!object[PERMALINK] && orig) {
      throw new Error(`expected object.${PERMALINK}`)
    }

    const expectedOrig = typeof orig === 'string' ? orig : getStringLink(orig)
    if (object[PERMALINK] !== expectedOrig) {
      throw new Error(`object.${PERMALINK} and "orig" don't match`)
    }

    if (prev[PERMALINK] && prev[PERMALINK] !== object[PERMALINK]) {
      throw new Error(`expected object.${PERMALINK} === prev.${PERMALINK}`)
    }
  }
}

const ensureNonZeroVersion = object => {
  if (!object[VERSION]) {
    throw new Error(`expected non-zero version ${VERSION}`)
  }
}

const createMerkleTree = (obj, opts) => {
  if (obj[SIG]) throw new Error('merkle tree should not include signature')

  const gen = merkleGenerator(getMerkleOpts(opts))

  // list with flat-tree indices
  const nodes = []
  const keys = getKeys(obj)
  keys.forEach(function (key, i) {
    gen.next(stringify(key), nodes)
    gen.next(stringify(obj[key]), nodes)
  })

  nodes.push.apply(nodes, gen.finalize())
  const sorted = nodes.sort(byIndexSort)
  return {
    nodes: sorted,
    roots: gen.roots,
    indices: getIndices(obj, keys)
  }
}

const prover = (object, opts) => {
  const tree = createMerkleTree(object, getMerkleOpts(opts))
  const leaves = []
  const builder = {
    add: function (opts) {
      typeforce({
        property: typeforce.String,
        key: '?Boolean',
        value: '?Boolean'
      }, opts, true)

      const prop = opts.property
      const propNodes = tree.indices[prop]
      if (opts.key) leaves.push(tree.nodes[propNodes.key])
      if (opts.value) leaves.push(tree.nodes[propNodes.value])

      return builder
    },
    leaves: function () {
      return leaves.slice()
    },
    proof: function (cb) {
      return prove({
        nodes: tree.nodes,
        leaves: leaves
      }, cb)
    }
  }

  return builder
}

const prove = (opts) => {
  // return nodes needed to prove leaves at leafIndices are part of the tree
  typeforce({
    nodes: typeforce.arrayOf(types.merkleNode),
    leaves: typeforce.arrayOf(types.merkleLeaf)
  }, opts)

  const prover = merkleProofs.proofGenerator(opts.nodes)
  const leaves = opts.leaves
  for (var i = 0; i < leaves.length; i++) {
    prover.add(leaves[i])
  }

  return prover.proof()
}

const verifyProof = (opts, cb) => {
  typeforce({
    proof: typeforce.arrayOf(types.merkleNode),
    node: types.merkleNode
  }, opts)

  const vOpts = getMerkleOpts(opts)
  vOpts.proof = opts.proof

  const verify = merkleProofs.verifier(vOpts)
  return verify(opts.node)
}

// function importPriv (key, curve) {
//   return typeof key === 'string'
//     ? curve.keyFromPrivate(key)
//     : key
// }

// function importPub (key, curve) {
//   return typeof key === 'string'
//     ? curve.keyFromPublic(key)
//     : key
// }

const alphabetical = (a, b) => {
  const al = a.toLowerCase()
  const bl = b.toLowerCase()
  return al < bl ? -1 : al > bl ? 1 : 0
}

const byIndexSort = (a, b) => {
  return a.index - b.index
}

const getMerkleOpts = (opts) => {
  const defaults = module.exports.DEFAULT_MERKLE_OPTS
  if (!opts) return defaults

  return {
    leaf: opts.leaf || defaults.leaf,
    parent: opts.parent || defaults.parent
  }
}

const getLeaves = (nodes) => {
  return nodes.filter(function (n) {
    return n.index % 2 === 0
  })
}

const find = (arr, match) => {
  if (arr.find) return arr.find(match)

  for (let i = 0; i < arr.length; i++) {
    if (match(arr[i], i)) return arr[i]
  }
}

const getKeys = (obj) => {
  return Object.keys(obj).sort(alphabetical)
}

const getIndices = (obj, keys) => {
  keys = keys || getKeys(obj)
  const indices = {}
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]
    indices[key] = {
      key: flatTree.index(0, i * 2),
      value: flatTree.index(0, i * 2 + 1)
    }
  }

  return indices
}

const getKeyInputData = (objInfo) => {
  typeforce({
    sig: typeforce.Buffer,
  }, objInfo)

  return objInfo.sig
}

// function getSigData (sigInput) {
//   typeforce(types.sigInput, sigInput)

//   return sha256(Buffer.concat([
//     sigInput.merkleRoot,
//     new Buffer(sigInput.recipient, 'hex')
//   ]))
// }

const toPrivateKey = (priv) => {
  if (typeof priv === 'string') priv = toBuffer(priv)

  if (priv.length !== 32) priv = sha256(priv)

  while (!secp256k1.privateKeyVerify(priv)) {
    priv = sha256(priv)
  }

  return priv
}

const ensureSigned = (obj) => {
  if (!obj[SIG]) throw new Error('object must be signed')
}

const getHeader = (obj) => {
  ensureSigned(obj)
  const header = utils.pick(obj, HEADER_PROPS)
  for (let p in header) {
    const val = header[p]
    if (Buffer.isBuffer(val)) {
      header[p] = val.toString('base64')
    }
  }

  return header
}

const getBody = (obj) => {
  return utils.omit(obj, HEADER_PROPS)
}

const getStringLink = (obj) => {
  return getLink(obj, ENC)
}

const getLink = (obj, enc) => {
  if (Buffer.isBuffer(obj)) {
    if (obj.length === 32) {
      return enc ? obj.toString(enc) : obj
    }

    obj = JSON.parse(obj)
  }

  return toMerkleRoot(obj).toString(ENC)
}

const pubKeyFromObject = (object) => {
  return pubKeyFromHeader(getHeader(object))
}

const pubKeyFromHeader = (header, enc) => {
  return pubKeyFromHeaderHash(hashHeader(header, enc))
}

const hashHeader = (header, enc=ENC) => {
  return headerHashFn(stringify(header), enc)
}

const pubKeyFromHeaderHash = (hash) => {
  return privToPub(toPrivateKey(hash))
}

const prevPubKeyFromObject = (object) => {
  return prevPubKeyFromHeaderHash(getHeader(object))
}

const prevPubKeyFromHeaderHash = (headerHash, enc=ENC) => {
  return pubKeyFromHeaderHash(iterateHeaderHash(headerHash, enc), enc)
}

const iterateHeaderHash = (headerHash, enc=ENC) => {
  return headerHashFn(new Buffer(headerHash, enc), enc)
}

const toBuffer = (str, enc=ENC) => {
  return Buffer.isBuffer(str) ? str : new Buffer(str, enc)
}

const privToPub = (priv) => {
  return {
    curve: CURVE,
    pub: secp256k1.publicKeyCreate(priv, false)
  }
}

const DEFAULT_MERKLE_OPTS = {
  leaf: function leaf (node) {
    return sha256(node.data)
  },
  parent: function parent (a, b) {
    return concatSha256(a.hash, b.hash)
  }
}

module.exports = {
  DEFAULT_MERKLE_OPTS,
  types,
  stringify,
  merkleHash: sha256,
  secp256k1,
  tree: createMerkleTree,
  merkleRoot: computeMerkleRoot,
  object: createObject,
  parseObject,
  nextVersion,
  sealPubKey: calcSealPubKey,
  sealPrevPubKey: calcSealPrevPubKey,
  verifySealPubKey: verifySealPubKey,
  verifySealPrevPubKey: verifySealPrevPubKey,
  sign: merkleAndSign,
  // message: createMessage,
  // validateMessage: validateMessage,
  // getSigPubKey: getSigPubKey,
  sigPubKey: getSigKey,
  verifySig: verifySig,
  verify: verifySig,
  validateVersioning,
  prove,
  prover,
  verifyProof,
  leaves: getLeaves,
  indices: getIndices,
  protobufs: proto,
  linkString: getStringLink,
  link: getLink,
  // prevSealLink: getSealedPrevLink,
  // prevLink: getPrevLink,
  header: getHeader,
  headerHash: getHeaderHash,
  body: getBody,
  // serializeMessage: serializeMessage,
  // unserializeMessage: unserializeMessage,
  genECKey: utils.genECKey,
  constants,
  utils: utils
}
