
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
const constants = require('./lib/constants')
const parallel = require('run-parallel')
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
  VERSION
} = constants

const HEADER_PROPS = [SIG]

module.exports = {
  DEFAULT_MERKLE_OPTS: {
    leaf: function leaf (node) {
      return sha256(node.data)
    },
    parent: function parent (a, b) {
      return concatSha256(a.hash, b.hash)
    }
  },
  types: types,
  stringify: stringify,
  merkleHash: sha256,
  secp256k1: secp256k1,
  tree: createMerkleTree,
  merkleRoot: computeMerkleRoot,
  object: createObject,
  parseObject: parseObject,
  nextVersion: nextVersion,
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
  // validateObject: validateObject,
  validateVersioning: validateVersioning,
  prove: prove,
  prover: prover,
  verifyProof: verifyProof,
  leaves: getLeaves,
  indices: getIndices,
  protobufs: proto,
  linkString: getStringLink,
  link: getLink,
  // prevSealLink: getSealedPrevLink,
  // prevLink: getPrevLink,
  header: getHeader,
  body: getBody,
  // serializeMessage: serializeMessage,
  // unserializeMessage: unserializeMessage,
  genECKey: utils.genECKey,
  constants: constants,
  utils: utils
}

function createObject (opts) {
  typeforce({
    object: types.rawObject,
    prev: typeforce.maybe(types.merkleRootOrObj),
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

function nextVersion (object, link) {
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

function merkleAndSign (opts, cb) {
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
function calcSealPubKey (opts) {
  typeforce({
    basePubKey: types.chainPubKey,
    object: typeforce.maybe(typeforce.Object)
  }, opts)

  return utils.publicKeyCombine([
    opts.basePubKey,
    pubKeyFromObject(opts.object)
  ])
}

function calcSealPrevPubKey (opts) {
  typeforce({
    basePubKey: types.chainPubKey,
    object: typeforce.maybe(typeforce.Object),
  }, opts)

  return utils.publicKeyCombine([
    opts.basePubKey,
    prevPubKeyFromObject(opts.object)
  ])
}

function verifySealPubKey (opts) {
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

function verifySealPrevPubKey (opts) {
  typeforce({
    sealPrevPubKey: types.chainPubKey
  }, opts)

  const expected = calcSealPrevPubKey(opts)
  return utils.ecPubKeysAreEqual(expected, opts.sealPrevPubKey)
}

/**
 * Calculate destination public key
 * used by the recipient of a transaction
 *
 * @param  {Object}   opts
 * @param  {Function} cb(?Error)
 */
// function validateObject (opts, cb) {
//   typeforce({
//     object: typeforce.Object
//   }, opts)

//   validateVersioning(opts)
//   return {
//     sigPubKey: getSigKey(opts)
//   }
// }

function parseObject (opts) {
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

function getSigKey (opts) {
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

function verifySig (opts) {
  try {
    return !!getSigKey(opts)
  } catch (err) {
    return false
  }
}

/**
 * validate object sequence
 * @param  {[type]} object     [description]
 * @param  {[type]} prev       [description]
 * @param  {[type]} merkleOpts [description]
 * @return {[type]}            [description]
 */
function validateVersioning (opts) {
  debugger
  const object = opts.object
  const prev = opts.prev
  if (object[PREVLINK] || prev) {
    if (object[PREVLINK] && !prev) {
      throw new Error('expected "prev"')
    }

    if (!object[PREVLINK] && prev) {
      throw new Error(`object missing property "${PREV}"`)
    }

    const expectedPrev = typeof prev === 'string' ? prev : getStringLink(prev)
    if (object[PREVLINK] !== expectedPrev) {
      throw new Error(`object[${PREV}] and "prev" don't match`)
    }
  }

  const orig = opts.orig
  if (object[PERMALINK] || orig) {
    if (object[PERMALINK] && !orig) {
      throw new Error('expected "orig"')
    }

    if (!object[PERMALINK] && orig) {
      throw new Error(`object missing property "${PERMALINK}"`)
    }

    const expectedOrig = typeof orig === 'string' ? orig : getStringLink(orig)
    if (object[PERMALINK] !== expectedOrig) {
      throw new Error(`object[${PERMALINK}] and "orig" don't match`)
    }

    if (prev[PERMALINK] && prev[PERMALINK] !== object[PERMALINK]) {
      throw new Error(`object and prev have different ${PERMALINK}`)
    }
  }
}

function createMerkleTree (obj, opts) {
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

function prover (object, opts) {
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

function prove (opts) {
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

function verifyProof (opts, cb) {
  typeforce({
    proof: typeforce.arrayOf(types.merkleNode),
    node: types.merkleNode
  }, opts)

  const vOpts = getMerkleOpts(opts)
  vOpts.proof = opts.proof

  const verify = merkleProofs.verifier(vOpts)
  return verify(opts.node)
}

function sha256 (data, enc) {
  return crypto.createHash('sha256').update(data).digest(enc)
}

function concatSha256 (a, b, enc) {
  return crypto.createHash('sha256').update(a).update(b).digest(enc)
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

function alphabetical (a, b) {
  const al = a.toLowerCase()
  const bl = b.toLowerCase()
  return al < bl ? -1 : al > bl ? 1 : 0
}

function byIndexSort (a, b) {
  return a.index - b.index
}

function getMerkleOpts (opts) {
  const defaults = module.exports.DEFAULT_MERKLE_OPTS
  if (!opts) return defaults

  return {
    leaf: opts.leaf || defaults.leaf,
    parent: opts.parent || defaults.parent
  }
}

function getLeaves (nodes) {
  return nodes.filter(function (n) {
    return n.index % 2 === 0
  })
}

function find (arr, match) {
  if (arr.find) return arr.find(match)

  for (let i = 0; i < arr.length; i++) {
    if (match(arr[i], i)) return arr[i]
  }
}

function getKeys (obj) {
  return Object.keys(obj).sort(alphabetical)
}

function getIndices (obj, keys) {
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

function getKeyInputData (objInfo) {
  typeforce({
    sig: typeforce.Buffer,
  }, objInfo)

  return objInfo.sig
}

function getMerkleRoot (tree) {
  return tree.roots[0].hash
}

function computeMerkleRoot (obj, opts) {
  const tree = createMerkleTree(obj, getMerkleOpts(opts))
  return getMerkleRoot(tree)
}

function toMerkleRoot (merkleRootOrObj, opts) {
  return Buffer.isBuffer(merkleRootOrObj)
    ? merkleRootOrObj
    : computeMerkleRoot(getBody(merkleRootOrObj), opts)
}

// function getSigData (sigInput) {
//   typeforce(types.sigInput, sigInput)

//   return sha256(Buffer.concat([
//     sigInput.merkleRoot,
//     new Buffer(sigInput.recipient, 'hex')
//   ]))
// }

function toPrivateKey (priv) {
  if (priv.length !== 32) priv = sha256(priv)

  while (!secp256k1.privateKeyVerify(priv)) {
    priv = sha256(priv)
  }

  return priv
}

function ensureSigned (obj) {
  if (!obj[SIG]) throw new Error('object must be signed')
}

function getHeader (obj) {
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

function getBody (obj) {
  return utils.omit(obj, HEADER_PROPS)
}

function getStringLink (obj) {
  return getLink(obj, 'hex')
}

function getLink (obj, enc) {
  if (Buffer.isBuffer(obj)) {
    if (obj.length === 32) {
      return enc ? obj.toString(enc) : obj
    }

    obj = JSON.parse(obj)
  }

  return toMerkleRoot(obj).toString('hex')
}

function pubKeyFromObject (object) {
  return pubKeyFromHeader(getHeader(object))
}

function pubKeyFromHeader (header, enc) {
  return pubKeyFromHeaderHash(getHeaderHash(header, enc))
}

function getHeaderHash (header, enc='hex') {
  return sha256(stringify(header), enc)
}

function pubKeyFromHeaderHash (hash) {
  return privToPub(toPrivateKey(hash))
}

function prevPubKeyFromObject (object) {
  return prevPubKeyFromHeader(getHeader(object))
}

function prevPubKeyFromHeader (header, enc) {
  // double hash header
  return pubKeyFromHeaderHash(sha256(getHeaderHash(header, enc)))
}

function privToPub (priv) {
  return {
    curve: CURVE,
    pub: secp256k1.publicKeyCreate(priv, false)
  }
}
