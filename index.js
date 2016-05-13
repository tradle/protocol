
'use strict'

const crypto = require('crypto')
const clone = require('xtend')
const extend = require('xtend/mutable')
const typeforce = require('typeforce')
const stringify = require('json-stable-stringify')
const merkleProofs = require('merkle-proofs')
const merkleGenerator = require('merkle-tree-stream/generator')
const secp256k1 = require('secp256k1')
const constants = require('@tradle/constants')
const parallel = require('run-parallel')
const proto = require('./lib/proto')
const utils = require('./lib/utils')
const types = require('./lib/types')
const DEFAULT_CURVE = 'secp256k1'
const SIG = constants.SIG
const TYPE = constants.TYPE
const PREV = constants.PREV_HASH
const ORIG = constants.ROOT_HASH
const HEADER_PROPS = [SIG]

const DEFAULT_MERKLE_OPTS = {
  leaf: function (node) {
    return sha256(node.data)
  },
  parent: function (a, b) {
    return concatSha256(a.hash, b.hash)
  }
}

module.exports = {
  types: types,
  stringify: stringify,
  merkleHash: sha256,
  secp256k1: secp256k1,
  tree: createMerkleTree,
  merkleRoot: computeMerkleRoot,
  object: createObject,
  sealPubKey: calcSealPubKey,
  sealPrevPubKey: calcSealPrevPubKey,
  verifySealPubKey: verifySealPubKey,
  verifySealPrevPubKey: verifySealPrevPubKey,
  sign: merkleAndSign,
  message: createMessage,
  validateMessage: validateMessage,
  // getSigPubKey: getSigPubKey,
  sigPubKey: getSigKey,
  validateObject: validateObject,
  validateVersioning: validateVersioning,
  prove: prove,
  prover: prover,
  verifyProof: verifyProof,
  leaves: getLeaves,
  indices: getIndices,
  proto: proto,
  link: getLink,
  prevSealLink: getSealedPrevLink,
  // prevLink: getPrevLink,
  header: getHeader,
  body: getBody,
  serializeMessage: serializeMessage,
  unserializeMessage: unserializeMessage,
  genECKey: utils.genECKey
}

function createObject (opts) {
  typeforce({
    object: typeforce.Object,
    prev: typeforce.maybe(types.merkleRootOrObj),
    orig: typeforce.maybe(types.merkleRootOrObj)
  }, opts, true)

  // shallow copy not too safe
  const obj = getBody(opts.object)
  if (opts.prev) {
    obj[PREV] = getLink(opts.prev)
  }

  if (opts.orig) {
    obj[ORIG] = getLink(opts.orig)
  }

  return obj
}

function createMessage (opts, cb) {
  typeforce({
    recipientPubKey: types.ecPubKey,
    sender: types.sender,
    object: typeforce.Object,
    prev: typeforce.maybe(typeforce.Object)
  }, opts)

  const object = opts.object
  if (!object[SIG]) throw new Error('object must be signed')

  const raw = {
    senderPubKey: opts.sender.sigPubKey,
    recipientPubKey: opts.recipientPubKey,
    object: opts.object
  }

  if (opts.prev) {
    raw.prev = getLink(opts.prev)
  }

  const message = createObject({
    object: raw
  })

  merkleAndSign({
    object: message,
    sender: opts.sender
  }, cb)
}

function validateMessage (opts) {
  typeforce({
    // roles reversed from createMessage
    senderPubKey: types.ecPubKey,
    recipientPubKey: types.ecPubKey,
    message: typeforce.Object,
    prev: typeforce.maybe(typeforce.Object)
  }, opts)

  validateObject({
    object: opts.message,
    senderPubKey: opts.senderPubKey
  })

  const message = opts.message
  // if (!message[SIG]) throw new Error('object must be signed')

  // const sigPubKey = utils.getSigKey(msgSigData, message[SIG])
  // if (!sigPubKey || !sigPubKey.value.equals(opts.senderPubKey)) {
  //   throw new Error('signature did not match public key')
  // }

  if (message[PREV] || opts.prev) {
    if (message[PREV] && !opts.prev) {
      throw new Error('expected "prev"')
    }

    if (!message[PREV] && opts.prev) {
      throw new Error(`message missing property "${PREV}"`)
    }

    const expectedPrev = getLink(opts.prev)
    if (!message[PREV].equals(expectedPrev)) {
      throw new Error(`object[${PREV}] and "prev" don't match`)
    }
  }
}

function merkleAndSign (opts, cb) {
  typeforce({
    sender: types.sender,
    object: typeforce.Object
  }, opts)

  const object = opts.object
  // if (object[SIG]) throw new Error('object is already signed')

  const tree = createMerkleTree(getBody(object), getMerkleOpts(opts))
  const merkleRoot = getMerkleRoot(tree)
  if (object[SIG]) return onsigned()

  doSign(opts.sender, merkleRoot, function (err, sig) {
    if (err) return cb(err)

    object[SIG] = utils.sigToString(sig)
    onsigned()
  })

  function onsigned (err) {
    cb(null, {
      tree: tree,
      merkleRoot: merkleRoot,
      sig: object[SIG],
      object: object
    })
  }
}

function doSign (sender, data, cb) {
  typeforce(types.sender, sender)
  typeforce(typeforce.Buffer, data)

  sender.sign(data, function (err, sig) {
    if (err) return cb(err)

    const encodedSig = proto.schema.ECSignature.encode({
      pubKey: sender.sigPubKey,
      sig: sig
    })

    cb(null, encodedSig)
  })
}

/**
 * calculate a public key that seals `link` based on `basePubKey`
 */
function calcSealPubKey (opts) {
  typeforce({
    basePubKey: types.chainPubKey,
    object: typeforce.maybe(typeforce.Object),
    link: typeforce.maybe(typeforce.Buffer)
  }, opts, true)

  const link = opts.link || getLink(opts.object)
  return utils.publicKeyCombine([
    opts.basePubKey,
    pubKeyFromLink(link)
  ])
}

function calcSealPrevPubKey (opts) {
  typeforce({
    basePubKey: types.chainPubKey,
    object: typeforce.maybe(typeforce.Object)
  }, opts, true)

  const link = getSealedPrevLink(opts.object)
  return utils.publicKeyCombine([
    opts.basePubKey,
    pubKeyFromLink(link)
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

  return utils.pubKeysAreEqual(expected, opts.sealPubKey)
}

function verifySealPrevPubKey (opts) {
  typeforce({
    sealPubKey: types.chainPubKey
  }, opts)

  const expected = calcSealPrevPubKey(opts)
  return utils.pubKeysAreEqual(expected, opts.sealPubKey)
}

/**
 * Calculate destination public key
 * used by the recipient of a transaction
 *
 * @param  {Object}   opts
 * @param  {Function} cb(?Error)
 */
function validateObject (opts, cb) {
  typeforce({
    object: typeforce.Object,
    senderPubKey: types.ecPubKey
  }, opts)

  validateVersioning(opts)
  const okey = getSigKey(opts)
  if (!okey || !utils.pubKeysAreEqual(okey, opts.senderPubKey)) {
    throw new Error('bad signature')
  }
}

function getSigKey (opts) {
  typeforce({
    object: typeforce.Object
  }, opts)

  const object = opts.object
  const sig = utils.sigFromString(object[SIG])
  // necessary step to make sure key encoded
  // in signature is that key used to sign
  const merkleRoot = computeMerkleRoot(getBody(object), getMerkleOpts(opts))
  return utils.getSigKey(merkleRoot, sig)
}

/**
 * validate object sequence
 * @param  {[type]} object     [description]
 * @param  {[type]} prev       [description]
 * @param  {[type]} merkleOpts [description]
 * @return {[type]}            [description]
 */
function validateVersioning (opts) {
  const object = opts.object
  const prev = opts.prev
  if (object[PREV] || prev) {
    if (object[PREV] && !prev) {
      throw new Error('expected "prev"')
    }

    if (!object[PREV] && prev) {
      throw new Error(`object missing property "${PREV}"`)
    }

    const expectedPrev = Buffer.isBuffer(prev) ? prev : getLink(prev)
    if (!object[PREV].equals(expectedPrev)) {
      throw new Error(`object[${PREV}] and "prev" don't match`)
    }
  }

  const orig = opts.orig
  if (object[ORIG] || orig) {
    if (object[ORIG] && !orig) {
      throw new Error('expected "orig"')
    }

    if (!object[ORIG] && orig) {
      throw new Error(`object missing property "${ORIG}"`)
    }

    const expectedOrig = Buffer.isBuffer(orig) ? orig : getLink(orig)
    if (!object[ORIG].equals(expectedOrig)) {
      throw new Error(`object[${ORIG}] and "orig" don't match`)
    }
  }
}

function createMerkleTree (obj, opts) {
  if (typeof opts === 'function') {
    cb = opts
    opts = null
  }

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
  const sorted = new Array(nodes.length)
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i]
    const idx = node.index
    sorted[idx] = node
  }

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

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}

function concatSha256 (a, b) {
  return crypto.createHash('sha256').update(a).update(b).digest()
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
  if (!opts) return DEFAULT_MERKLE_OPTS

  return {
    leaf: opts.leaf || DEFAULT_MERKLE_OPTS.leaf,
    parent: opts.parent || DEFAULT_MERKLE_OPTS.parent
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
    const kIdx = i * 4
    indices[key] = {
      key: kIdx,
      value: kIdx + 2
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

function getSigData (sigInput) {
  typeforce(types.sigInput, sigInput)

  return sha256(Buffer.concat([
    sigInput.merkleRoot,
    new Buffer(sigInput.recipient, 'hex')
  ]))
}

function toPrivateKey (priv) {
  if (priv.length !== 32) priv = sha256(priv)

  while (!secp256k1.privateKeyVerify(priv)) {
    priv = sha256(priv)
  }

  return priv
}

function getHeader (obj) {
  if (!obj[SIG]) throw new Error('object must be signed')

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

function getLink (obj) {
  if (Buffer.isBuffer(obj)) return obj

  const header = getHeader(obj)
  return sha256(stringify(header))
}

function keyFromLink (link) {
  return toPrivateKey(link)
}

function pubKeyFromLink (link) {
  return {
    curve: 'secp256k1',
    pub: secp256k1.publicKeyCreate(keyFromLink(link))
  }
}

function pubKeyFromObject (object) {
  return pubKeyFromLink(getLink(object))
}

// function getPrevLink (objectOrLink) {
//   const prev = Buffer.isBuffer(object) ? objectOrLink : object[PREV]
//   return prev && sha256(prev)
// }

function getSealedPrevLink (object) {
  const prevLink = Buffer.isBuffer(object) ? object : object[PREV]
  if (!prevLink) return

  typeforce(typeforce.Buffer, prevLink)
  return sha256(prevLink)
}

// function getPrevMessageLink (prevMsg) {
//   typeforce(typeforce.Buffer, prevMsg[SIG])
//   return sha256(prevMsg[SIG])
// }

// function getMsgSigData (opts) {
//   return sha256(
//     Buffer.concat([
//       opts.object[SIG],
//       opts.senderPubKey,
//       opts.recipientPubKey
//     ])
//   )
// }

// function merkleSignMerkle (data, key, merkleOpts, cb) {
//   const shareMerkleRoot = computeMerkleRoot(share, merkleOpts)
//   share[SIG] = utils.sign(shareMerkleRoot, sigKey)
// }

function serializeMessage (msg) {
  return proto.Message.encode(msg)
}

function unserializeMessage (msg) {
  return proto.Message.decode(msg)
}
