
'use strict'

const crypto = require('crypto')
const typeforce = require('typeforce')
const stringify = require('json-stable-stringify')
const merkleProofs = require('merkle-proofs')
const merkleGenerator = require('merkle-tree-stream/generator')
const secp256k1 = require('secp256k1')
const flatTree = require('flat-tree')
const constants = require('@tradle/constants')
const Embed = require('@tradle/embed')
const Errors = require('./lib/errors')
const { InvalidInput, InvalidVersion } = Errors
const proto = require('./lib/proto')
const utils = require('./lib/utils')
const types = require('./lib/types')
const {
  ensureUnsigned,
  ensureSigned,
  ensureTimestampIncreased,
  ensureNonZeroVersion
} = types

const {
  SIG,
  PREVLINK,
  PERMALINK,
  VERSION,
  PREVHEADER,
  TIMESTAMP,
  WITNESSES,
  PROTOCOL_VERSION
} = constants

const { HEADER_PROPS, LINK_HEADER_PROPS } = require('./lib/constants')
const ENC = 'hex'
const getSemverMajor = semver => parseInt(semver.split('.')[0])

const CURRENT_PROTOCOL_VERSION = require('./package.json').version
const VERSION_BEFORE_PROTOCOL_VERSION_PROP = '4.0.0'
const CURVE = 'secp256k1'

const sha256 = (data, enc) => {
  return crypto.createHash('sha256').update(data).digest(enc)
}

const concatSha256 = (a, b, enc) => {
  return crypto.createHash('sha256').update(a).update(b).digest(enc)
}

const getSealHeaderHash = object => hashHeader(getSealHeader(object))

const getMerkleRoot = (tree) => {
  return tree.roots[0].hash
}

const computeMerkleRoot = (obj, opts) => {
  const tree = createMerkleTree(obj, getMerkleOpts(opts))
  return getMerkleRoot(tree)
}

const headerHashFn = sha256

const toMerkleRoot = (merkleRootOrObj, opts) => {
  return Buffer.isBuffer(merkleRootOrObj)
    ? merkleRootOrObj
    : computeMerkleRoot(getBody(merkleRootOrObj), opts)
}

const createObject = (opts) => {
  typeforce({
    object: types.createObjectInput,
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

  if (obj[PREVLINK] || obj[PERMALINK] || obj[PREVHEADER]) {
    ensureNonZeroVersion(obj)
  }

  if (!obj[PROTOCOL_VERSION]) {
    obj[PROTOCOL_VERSION] = CURRENT_PROTOCOL_VERSION
  }

  if (!obj[TIMESTAMP]) {
    obj[TIMESTAMP] = Date.now()
  }

  return obj
}

const nextVersion = (object, link) => {
  const scaffold = scaffoldNextVersion(object, { link })
  const clean = utils.omit(object, HEADER_PROPS)
  return utils.extend(clean, scaffold)
}

const scaffoldNextVersion = (object, links = {}) => {
  const { link, permalink } = getLinks(utils.extend({ object }, links))
  const headerHash = getSealHeaderHash(object)
  return {
    [PREVLINK]: link,
    [PERMALINK]: permalink,
    [PREVHEADER]: headerHash,
    [VERSION]: (object[VERSION] || 0) + 1,
    [TIMESTAMP]: Date.now()
  }
}

const merkleAndSign = (opts, cb) => {
  typeforce({
    author: types.author,
    object: types.signObjectInput
  }, opts)

  const { author, object } = opts

  ensureUnsigned(object)

  const tree = createMerkleTree(getBody(object), getMerkleOpts(opts))
  const merkleRoot = getMerkleRoot(tree)
  signMerkleRoot({ author, merkleRoot }, (err, sig) => {
    if (err) return cb(err)

    const signed = utils.extend({ [SIG]: sig }, object)
    cb(null, {
      tree: tree,
      merkleRoot: merkleRoot,
      sig: sig,
      object: signed
    })
  })
}

const signMerkleRoot = (opts, cb) => {
  typeforce({
    author: types.author,
    merkleRoot: typeforce.Buffer
  }, opts)

  const { author, merkleRoot } = opts
  author.sign(merkleRoot, function (err, sig) {
    if (err) return cb(err)

    const encodedSig = utils.encodeSig({
      pubKey: author.sigPubKey,
      sig: sig
    })

    sig = utils.sigToString(encodedSig)
    cb(null, sig)
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
  if (!headerHash) headerHash = hashHeader(getSealHeader(object))

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
      throw new InvalidInput(`expected object.${PREVHEADER}`)
    }
  } else if (!prevHeaderHash) {
    throw new InvalidInput('expected "object" or "prevHeaderHash"')
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

  const { object } = opts
  ensureSigned(object)

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

  const { object, verify } = opts
  // necessary step to make sure key encoded
  // in signature is that key used to sign
  const merkleRoot = toMerkleRoot(object, opts)
  return utils.getSigKey(merkleRoot, object[SIG], verify)
}

const verifyWitnesses = opts => {
  const { object, verify } = opts
  return getWitnesses(object).every(witnessed => {
    return verifySig({ object: witnessed, verify })
  })
}

const fromWitness = ({ object, witness }) => {
  typeforce(types.witness, witness)
  return utils.extend(getBody(object), {
    [SIG]: witness.s
  })
}

const verifyWitness = ({ object, witness, verify }) => verifySig({
  object: fromWitness({ object, witness }),
  verify
})

const getWitnesses = object => (object[WITNESSES] || [])
  .map(witness => fromWitness({ object, witness }))

const verifySig = (opts) => {
  try {
    return !!getSigKey(opts)
  } catch (err) {
    return false
  }
}

const ensurePrevHeader = object => {
  if (object[PREVLINK] && !object[PREVHEADER]) {
    throw new InvalidInput(`expected object to have ${PREVHEADER}`)
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
  const validatePrev = object[PREVLINK] || object[VERSION] !== 0 || prev
  const validateOrig = object[PERMALINK] || object[VERSION] !== 0 || orig
  if (validatePrev || validateOrig) {
    ensureNonZeroVersion(object)
    ensurePrevHeader(object)
    ensureTimestampIncreased(object, prev)
  } else {
    if (object[VERSION] && object[VERSION] !== 0) {
      throw new InvalidVersion(`expected object.${VERSION} to be 0`)
    }
  }

  if (validatePrev) {
    if (!object[PREVLINK]) throw new InvalidInput(`expected object.${PREVLINK}`)
    if (!prev) throw new InvalidInput('expected "prev"')
    if (object[PREVLINK] !== getStringLink(prev)) {
      throw new InvalidInput(`object.${PREVLINK} and "prev" don't match`)
    }

    if (object[PREVHEADER] !== getSealHeaderHash(prev)) {
      throw new InvalidInput(`expected object.${PREVHEADER} to equal the header hash of "prev"`)
    }
  }

  if (validateOrig) {
    if (!object[PERMALINK]) throw new InvalidInput(`expected object.${PERMALINK}`)

    if (object[PERMALINK] && !orig) {
      throw new InvalidInput('expected "orig"')
    }

    if (!object[PERMALINK] && orig) {
      throw new InvalidInput(`expected object.${PERMALINK}`)
    }

    const expectedOrig = typeof orig === 'string' ? orig : getStringLink(orig)
    if (object[PERMALINK] !== expectedOrig) {
      throw new InvalidInput(`object.${PERMALINK} and "orig" don't match`)
    }

    if (prev[PERMALINK] && prev[PERMALINK] !== object[PERMALINK]) {
      throw new InvalidInput(`expected object.${PERMALINK} === prev.${PERMALINK}`)
    }
  }
}

const preProcessForMerklization = (obj, merkleOpts) => {
  const protocolVersion = obj[PROTOCOL_VERSION] || VERSION_BEFORE_PROTOCOL_VERSION_PROP
  const major = getSemverMajor(protocolVersion)
  if (major > 4) {
    obj = utils.cloneDeep(obj)
    return normalizeEmbeddedMedia(obj, merkleOpts)
  }

  return obj
}

const normalizeEmbeddedMedia = (obj, merkleOpts) => {
  merkleOpts = getMerkleOpts(merkleOpts)
  const getHashHex = data => merkleOpts.leaf({ data }).toString('hex')

  utils.traverse(obj).forEach(function (value) {
    if (typeof value !== 'string') return

    if (Embed.isKeeperUri(value)) {
      const { hash } = Embed.parseKeeperUri(value)
      this.update(hash)
      return
    }

    if (value.startsWith('data:')) {
      try {
        const buf = Embed.decodeDataURI(value)
        const hash = getHashHex(buf)
        this.update(hash)
      } catch (err) {
        // ignore
      }
    }
  })

  return obj
}

const merkleTreeFromHashes = (hashes, opts) => {
  const merkleOpts = getMerkleOpts(opts)
  const gen = merkleGenerator(merkleOpts)
  const nodes = []
  hashes.forEach(hash => {
    if (!Buffer.isBuffer(hash)) {
      throw new InvalidInput('expected each hash to be a Buffer object')
    }
  })

  hashes.forEach(hash => gen.next(hash, nodes))
  nodes.push.apply(nodes, gen.finalize())
  const tree = {
    nodes,
    roots: gen.roots
  }

  tree.root = getMerkleRoot(tree)
  return tree
}

const createMerkleTree = (obj, opts) => {
  if (obj[SIG]) throw new InvalidInput('merkle tree should not include signature')

  const merkleOpts = getMerkleOpts(opts)
  const gen = merkleGenerator(merkleOpts)

  obj = preProcessForMerklization(obj, merkleOpts)

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
  for (let i = 0; i < leaves.length; i++) {
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

// Memo: const getKeyInputData = (objInfo) => {
// Memo:   typeforce({
// Memo:     sig: typeforce.Buffer
// Memo:   }, objInfo)
// Memo:
// Memo:   return objInfo.sig
// Memo: }

// Memo: function getSigData (sigInput) {
// Memo:   typeforce(types.sigInput, sigInput)
// Memo:
// Memo:   return sha256(Buffer.concat([
// Memo:     sigInput.merkleRoot,
// Memo:     new Buffer(sigInput.recipient, 'hex')
// Memo:   ]))
// Memo: }

const toPrivateKey = (priv) => {
  if (typeof priv === 'string') priv = toBuffer(priv)

  if (priv.length !== 32) priv = sha256(priv)

  while (!secp256k1.privateKeyVerify(priv)) {
    priv = sha256(priv)
  }

  return priv
}

const getHeader = (obj, props) => {
  ensureSigned(obj)
  const header = utils.pick(obj, props)
  for (const p in header) {
    const val = header[p]
    if (Buffer.isBuffer(val)) {
      header[p] = val.toString('base64')
    }
  }

  return header
}

const getSealHeader = obj => getHeader(obj, HEADER_PROPS)
const getLinkHeader = obj => getHeader(obj, LINK_HEADER_PROPS)

const getBody = (obj) => {
  return utils.omit(obj, HEADER_PROPS)
}

const getLink = (obj, enc = ENC) => {
  ensureSigned(obj)
  if (Buffer.isBuffer(obj)) {
    if (obj.length === 32) {
      return enc ? obj.toString(enc) : obj
    }

    obj = JSON.parse(obj)
  }

  return hashHeader(getLinkHeader(obj, enc))
}

const getStringLink = getLink
const getLinks = wrapper => {
  typeforce({
    object: typeforce.maybe(typeforce.Object),
    permalink: typeforce.maybe(typeforce.String),
    link: typeforce.maybe(typeforce.String),
    prevLink: typeforce.maybe(typeforce.String)
  }, wrapper)

  const object = wrapper.object
  const link = wrapper.link || (object && getStringLink(object))
  const links = {
    link: link,
    permalink: wrapper.permalink || (object ? object[PERMALINK] || link : null)
  }

  const prevLink = wrapper.prevLink || (object && object[PREVLINK])
  if (prevLink) links.prevLink = prevLink

  if (!links.permalink && links.prevLink) {
    throw new InvalidInput('expected "permalink"')
  }

  return links
}

const pubKeyFromObject = (object) => {
  return pubKeyFromHeader(getSealHeader(object))
}

const pubKeyFromHeader = (header, enc) => {
  return pubKeyFromHeaderHash(hashHeader(header, enc))
}

const hashHeader = (header, enc = ENC) => {
  return headerHashFn(stringify(header), enc)
}

const pubKeyFromHeaderHash = (hash) => {
  return privToPub(toPrivateKey(hash))
}

// Memo: const prevPubKeyFromObject = (object) => {
// Memo:   return prevPubKeyFromHeaderHash(getSealHeader(object))
// Memo: }

const prevPubKeyFromHeaderHash = (headerHash, enc = ENC) => {
  return pubKeyFromHeaderHash(iterateHeaderHash(headerHash, enc), enc)
}

const iterateHeaderHash = (headerHash, enc = ENC) => {
  return headerHashFn(Buffer.from(headerHash, enc), enc)
}

const getIteratedHeaderHash = object => iterateHeaderHash(getSealHeaderHash(object))

const toBuffer = (str, enc = ENC) => {
  return Buffer.isBuffer(str) ? str : Buffer.from(str, enc)
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

const signAsWitness = (opts, cb) => {
  const { object, permalink } = opts
  ensureSigned(object)
  if (!permalink) throw new InvalidInput('expected string "permalink" of signer\'s identity')

  const unsigned = getBody(object)
  merkleAndSign(utils.extend({}, opts, { object: unsigned }), (err, result) => {
    if (err) return cb(err)

    const { sig } = result
    const witnesses = object[WITNESSES] || []
    witnesses.push(wrapWitnessSig({
      author: permalink,
      sig
    }))

    cb(null, utils.extend({}, object, {
      [WITNESSES]: witnesses
    }))
  })
}

const wrapWitnessSig = opts => {
  typeforce({
    author: typeforce.String,
    sig: typeforce.String
  }, opts)

  return {
    a: opts.author,
    s: opts.sig
  }
}

const unwrapWitnessSig = opts => {
  typeforce({
    a: typeforce.String,
    s: typeforce.String
  }, opts)

  return {
    author: opts.a,
    sig: opts.s
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
  merkleTreeFromHashes,
  preProcessForMerklization,
  object: createObject,
  parseObject,
  nextVersion,
  scaffoldNextVersion,
  sealPubKey: calcSealPubKey,
  sealPrevPubKey: calcSealPrevPubKey,
  verifySealPubKey: verifySealPubKey,
  verifySealPrevPubKey: verifySealPrevPubKey,
  sign: merkleAndSign,
  signMerkleRoot,
  signAsWitness,
  witness: signAsWitness,
  // message: createMessage,
  // validateMessage: validateMessage,
  // getSigPubKey: getSigPubKey,
  sigPubKey: getSigKey,
  verifySig: verifySig,
  verify: verifySig,
  verifyWitnesses,
  verifyWitness,
  wrapWitnessSig,
  unwrapWitnessSig,
  validateVersioning,
  prove,
  prover,
  verifyProof,
  leaves: getLeaves,
  indices: getIndices,
  protobufs: proto,
  linkString: getStringLink,
  link: getLink,
  links: getLinks,
  // prevSealLink: getSealedPrevLink,
  // prevLink: getPrevLink,
  header: getSealHeader,
  headerHash: getSealHeaderHash,
  iteratedHeaderHash: getIteratedHeaderHash,
  iterateHeaderHash,
  body: getBody,
  // serializeMessage: serializeMessage,
  // unserializeMessage: unserializeMessage,
  genECKey: utils.genECKey,
  constants,
  utils,
  Errors,
  version: CURRENT_PROTOCOL_VERSION
}
