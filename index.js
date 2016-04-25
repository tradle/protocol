
'use strict'

const crypto = require('crypto')
const extend = require('xtend')
const typeforce = require('typeforce')
const merkleProofs = require('merkle-proofs')
const merkleGenerator = require('merkle-tree-stream/generator')
const ec = require('elliptic').ec
const secp256k1 = ec('secp256k1')
// const secp256k1Native = require('secp256k1')
// const ed25519 = ec('ed25519')
const BN = require('bn.js')
// const G = secp256k1.g
// const N = BN.red(secp256k1.n)
// const MAX_LEAVES = 0xffff
const DATA_NODE_TYPE = typeforce.compile({
  data: typeforce.Buffer,
  hash: typeforce.Buffer,
  index: typeforce.Number
})

const NODE_TYPE = typeforce.compile({
  hash: typeforce.Buffer,
  index: typeforce.Number
})

const DEFAULT_GEN_OPTS = {
  leaf: sha256,
  parent: concatSha256
}

module.exports = {
  tree: createMerkleTree,
  send: send,
  receive: receive,
  prove: prove,
  prover: prover,
  verify: verify,
  leaves: getLeaves,
  indices: getIndices
}

/**
 * Calculate destination public key
 * used by the sender of a transaction
 *
 * @param  {Object}   opts
 * @param  {?Function} cb(?Error, ?elliptic.KeyPair)
 */
function send (opts, cb) {
  typeforce({
    pub: typeforce.oneOf('String', 'Object'),
    message: 'Object'
  }, opts)

  const tree = createMerkleTree(opts)
  const merkleRoot = tree.roots[0].hash
  const msgKey = secp256k1.keyFromPrivate(merkleRoot)
  const pub = importPub(opts.pub, secp256k1)
  const msgKeyPub = msgKey.getPublic()
  const destPub = pub.add(msgKeyPub)
  const ret = {
    msgKey: msgKey,
    destKey: secp256k1.keyFromPublic(destPub),
    tree: tree,
    root: merkleRoot
  }

  return maybeAsync(ret, cb)
}

/**
 * Calculate destination public key
 * used by the recipient of a transaction
 *
 * @param  {Object}   opts
 * @param  {Function} cb(?Error, ?elliptic.KeyPair)
 */
function receive (opts, cb) {
  typeforce({
    priv: typeforce.oneOf('String', 'Object'),
    message: 'Object'
  }, opts)

  const tree = createMerkleTree(opts)
  const merkleRoot = tree.roots[0].hash
  const priv = importPriv(opts.priv, secp256k1)
  const destPriv = priv.add(new BN(merkleRoot)).mod(secp256k1.n)
  const ret = {
    tree: tree,
    msgKey: merkleRoot,
    destKey: secp256k1.keyFromPrivate(destPriv)
  }

  return maybeAsync(ret, cb)
}

function createMerkleTree (opts, cb) {
  typeforce({
    message: 'Object'
  }, opts)

  const gen = merkleGenerator(getMerkleOpts(opts))

  // list with flat-tree indices
  const nodes = []
  const msg = opts.message
  // const indexedTree = {}
  const keys = getKeys(msg)
  keys.forEach(function (key, i) {
    gen.next(key, nodes)
    gen.next(JSON.stringify(msg[key]), nodes)
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
    indices: getIndices(msg, keys)
  }

  return maybeAsync(ret, cb)
}

function prover (opts) {
  const tree = createMerkleTree(opts)
  const leaves = []
  const builder = {
    add: function (opts) {
      typeforce({
        property: 'String',
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
    nodes: typeforce.arrayOf(NODE_TYPE),
    leaves: typeforce.arrayOf(DATA_NODE_TYPE)
  }, opts)

  const prover = merkleProofs.proofGenerator(opts.nodes)
  const leaves = opts.leaves
  for (var i = 0; i < leaves.length; i++) {
    prover.add(leaves[i])
  }

  const proof = prover.proof()
  return maybeAsync(proof, cb)
}

function verify (opts, cb) {
  typeforce({
    proof: 'Array',
    node: NODE_TYPE
  }, opts)

  const vOpts = getMerkleOpts(opts)
  vOpts.proof = opts.proof

  const verify = merkleProofs.verifier(vOpts)
  const ret = verify(opts.node)
  return maybeAsync(ret, cb)
}

function sha256 (leaf) {
  return crypto.createHash('sha256').update(leaf.data).digest()
}

function concatSha256 (a, b) {
  return crypto.createHash('sha256').update(a.hash).update(b.hash).digest()
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
  return {
    leaf: opts.leaf || DEFAULT_GEN_OPTS.leaf,
    parent: opts.parent || DEFAULT_GEN_OPTS.parent
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
