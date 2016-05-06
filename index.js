
'use strict'

const crypto = require('crypto')
const extend = require('xtend')
const typeforce = require('typeforce')
const stringify = require('json-stable-stringify')
const merkleProofs = require('merkle-proofs')
const merkleGenerator = require('merkle-tree-stream/generator')
const secp256k1 = require('secp256k1')
const constants = require('@tradle/constants')
const utils = require('./lib/utils')
const types = require('./lib/types')
const SIG = constants.SIG
const PREV = constants.PREV_HASH
const ORIG = constants.ROOT_HASH
const PREV_TO_SENDER = constants.PREV_TO_SENDER || '_u'

const DEFAULT_MERKLE_OPTS = {
  leaf: function (node) {
    return sha256(node.data)
  },
  parent: function (a, b) {
    return concatSha256(a.hash, b.hash)
  },
}

module.exports = {
  secp256k1: secp256k1,
  tree: createMerkleTree,
  merkleRoot: computeMerkleRoot,
  object: createObject,
  separate: separate,
  send: send,
  receive: receive,
  validateSequence: validateSequence,
  processHeader: processHeader,
  prove: prove,
  prover: prover,
  verifyProof: verifyProof,
  leaves: getLeaves,
  indices: getIndices
}

function createObject (obj, opts) {
  typeforce({
    prevVersion: typeforce.maybe(types.merkleRootOrObj),
    origVersion: typeforce.maybe(types.merkleRootOrObj),
    prevObjectToSender: typeforce.maybe(typeforce.Object)
  }, opts)

  // not too safe
  obj = extend(obj)
  if (opts.prevVersion) {
    obj[PREV] = toMerkleRoot(opts.prevVersion, opts)
  }

  if (opts.origVersion) {
    obj[ORIG] = toMerkleRoot(opts.origVersion, opts)
  }

  if (opts.prevObjectToSender) {
    obj[PREV_TO_SENDER] = toMerkleRoot(opts.prevObjectToSender, opts)
  }

  return obj
}

// function share (opts, cb) {
//   typeforce({

//   }, opts)
// }

/**
 * Calculate destination public key
 * used by the sender of a transaction
 *
 * @param  {Object}   opts
 * @param  {?Function} cb(?Error, ?elliptic.KeyPair)
 */
function send (opts, cb) {
  typeforce({
    toKey: typeforce.Buffer,
    sigKey: typeforce.Buffer,
    object: typeforce.Object
  }, opts)

  const toKey = opts.toKey
  const sigKey = opts.sigKey
  const object = opts.object
  const tree = createMerkleTree(object, getMerkleOpts(opts))
  const merkleRoot = getMerkleRoot(tree)
  const sigInput = {
    merkleRoot: merkleRoot,
    recipient: toKey
  }

  const sigData = getSigData(sigInput)
  const sig = utils.sign(sigData, sigKey)
  const keyData = getKeyInputData(sigData, sig)
  const msgKey = toPrivateKey(keyData)
  const outputPub = secp256k1.publicKeyCombine([
    toKey,
    secp256k1.publicKeyCreate(msgKey)
  ])

  cb(null, {
    // msgKey: msgKey,
    outputKey: { pub: outputPub },
    tree: tree,
    merkleRoot: merkleRoot,
    header: {
      sig: sig,
      sigKey: secp256k1.publicKeyCreate(sigKey),
      sigInput: sigInput
    },
    object: object
  })
}

function separate (obj) {
  return {
    header: utils.pick(obj, 'sig', 'sigInput', 'sigKey'),
    object: utils.omit(obj, 'sig')
  }
}

function serialize (obj) {
  // use protocol-buffers
}

function processHeader (opts, cb) {
  typeforce({
    toKey: types.keyObj,
    header: types.header,
    object: typeforce.Object
  }, opts, true)

  cb = utils.asyncify(cb)
  const toKey = opts.toKey
  const object = opts.object
  const header = opts.header
  const tree = createMerkleTree(object, getMerkleOpts(opts))
  const merkleRoot = getMerkleRoot(tree)
  const sigData = getSigData(header.sigInput)
  const verified = utils.verify(sigData, header.sig, header.sigKey)
  if (!verified) return cb(new Error('bad signature'))

  const keyData = getKeyInputData(sigData, header.sig)
  const msgKey = toPrivateKey(keyData)

  let outputKey = {}
  if (toKey.priv) {
    try {
      outputKey.priv = secp256k1.privateKeyTweakAdd(toKey.priv, msgKey)
    } catch (err) {
      return cb(err)
    }
  } else {
    try {
      outputKey.pub = secp256k1.publicKeyCombine([
        toKey.pub,
        secp256k1.publicKeyCreate(msgKey)
      ])
    } catch (err) {
      return cb(err)
    }
  }

  cb(null, {
    tree: tree,
    // msgKey: msgKey,
    outputKey: outputKey,
    merkleRoot: merkleRoot
  })
}

/**
 * Calculate destination public key
 * used by the recipient of a transaction
 *
 * @param  {Object}   opts
 * @param  {Function} cb(?Error, ?elliptic.KeyPair)
 */
function receive (opts, cb) {
  cb = utils.asyncify(cb)
  try {
    validateSequence(opts.object, opts)
  } catch (err) {
    return cb(err)
  }

  processHeader(opts, cb)
}

function validateSequence (object, opts) {
  if (object[PREV] || opts.prevVersion) {
    if (object[PREV] && !opts.prevVersion) {
      throw new Error('expected "prevVersion"')
    }

    if (!object[PREV] && opts.prevVersion) {
      throw new Error(`object missing property "${PREV}"`)
    }

    const expectedPrev = toMerkleRoot(opts.prevVersion, getMerkleOpts(opts))
    if (!object[PREV].equals(expectedPrev)) {
      throw new Error(`object[${PREV}] and "prevVersion" don't match`)
    }
  }

  if (object[PREV_TO_SENDER] || opts.prevObjectFromSender) {
    if (object[PREV_TO_SENDER] && !opts.prevObjectFromSender) {
      throw new Error('expected "prevObjectFromSender"')
    }

    if (!object[PREV_TO_SENDER] && opts.prevObjectFromSender) {
      throw new Error(`object missing property "${PREV_TO_SENDER}"`)
    }

    const expectedPrev = toMerkleRoot(opts.prevObjectFromSender, getMerkleOpts(opts))
    if (!object[PREV_TO_SENDER].equals(expectedPrev)) {
      throw new Error(`object[${PREV_TO_SENDER}] and "prevObjectFromSender" don't match`)
    }
  }
}

function createMerkleTree (obj, opts, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = null
  }

  const gen = merkleGenerator(getMerkleOpts(opts))

  // list with flat-tree indices
  const nodes = []
  // const indexedTree = {}
  const keys = getKeys(obj)
  keys.forEach(function (key, i) {
    gen.next(key, nodes)
    gen.next(stringify(obj[key]), nodes)
  })

  nodes.push.apply(nodes, gen.finalize())
  const sorted = new Array(nodes.length)
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i]
    const idx = node.index
    sorted[idx] = node
  }

  const ret = {
    nodes: sorted,
    roots: gen.roots,
    indices: getIndices(obj, keys)
  }

  return maybeAsync(ret, cb)
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

function prove (opts, cb) {
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

  const proof = prover.proof()
  return maybeAsync(proof, cb)
}

function verifyProof (opts, cb) {
  typeforce({
    proof: typeforce.arrayOf(types.merkleNode),
    node: types.merkleNode
  }, opts)

  const vOpts = getMerkleOpts(opts)
  vOpts.proof = opts.proof

  const verify = merkleProofs.verifier(vOpts)
  const ret = verify(opts.node)
  return maybeAsync(ret, cb)
}

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}

function concatSha256 (a, b) {
  return crypto.createHash('sha256').update(a).update(b).digest()
}

function importPriv (key, curve) {
  return typeof key === 'string'
    ? curve.keyFromPrivate(key)
    : key
}

function importPub (key, curve) {
  return typeof key === 'string'
    ? curve.keyFromPublic(key)
    : key
}

function alphabetical (a, b) {
  const al = a.toLowerCase()
  const bl = b.toLowerCase()
  return al < bl ? -1 : al > bl ? 1 : 0
}

function byIndexSort (a, b) {
  return a.index - b.index
}

/**
 * return a value synchronously or asynchronously
 * depending on if callback is passed
 * @param  {anything}   val [description]
 * @param  {?Function}  cb  [description]
 * @return {anything}   val
 */
function maybeAsync (val, cb) {
  if (cb) {
    process.nextTick(function () {
      cb(null, val)
    })
  }

  return val
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

function getKeyInputData (sigData, sig) {
  typeforce(typeforce.Buffer, sigData)
  typeforce(typeforce.Buffer, sig)
  return Buffer.concat([sigData, sig])
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
    : computeMerkleRoot(merkleRootOrObj, opts)
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
