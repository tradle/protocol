import crypto = require('crypto')
import secp256k1 = require('secp256k1')
import typeforce = require('@tradle/typeforce')
import { Check } from '@tradle/typeforce/src/interfaces'
import type {
  Author, PublicKey, ProtocolRegistered,
  Signable, Signed, SignObject, Timestamped,
  Unsigned, Witness, Witnessed, Permalinked,
  HeaderProps, LinkHeaderProps, HeaderInput, Versionable
} from '@tradle/constants/types'
import * as Embed from '@tradle/embed'
import { MerkleProofGenerator, createVerifier, MiniNode, MerkleVerifierOpts } from '@tradle/merkle-proofs'
import MerkleGenerator = require('@tradle/merkle-tree-stream/generator')
import constants = require('@tradle/constants')
import stringify = require('json-stable-stringify')
import flatTree = require('flat-tree')
import omit = require('lodash/omit')
import pick = require('lodash/pick')
import cloneDeep = require('lodash/cloneDeep')
import * as traverse from 'traverse'
import * as types from './lib/types'
import * as utils from './lib/utils'
import * as schema from './lib/schema'
import * as Errors from './lib/errors'
import { version as CURRENT_PROTOCOL_VERSION } from './package.json'
import { HEADER_PROPS, LINK_HEADER_PROPS } from './lib/constants'
import type { Node } from '@tradle/merkle-tree-stream/types'
import type {
  CalcSealOpts, CalcSealPrevOpts, CreatedObject,
  EntireObjectInput, HeaderLess, IndexedTree, Indices,
  LinkWrapper, ProofEntry, Provable, Prover,
  SignMerkleOpts, SignOpts, TradleLeaf, TradleTree,
  TreeIndex, Verifiable, VerifyFn, VerifySealPrevPubKeyOpts,
  VerifySealPubKeyOpts, WitnessUnwrapped, Callback, MerkleOpts,
  GetSigKeyOpts
} from './lib/types'
import { DataURI } from '@tradle/embed'

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

const {
  ok, exists, notExists
} = utils

const { InvalidInput, InvalidVersion } = Errors

const ENC = 'hex'
const getSemverMajor = (semver: string): number => parseInt(semver.split('.')[0] as string)

export const VERSION_BEFORE_PROTOCOL_VERSION_PROP = '4.0.0'
export const CURVE = 'secp256k1'

function sha256 (data: crypto.BinaryLike): Buffer
function sha256 (data: crypto.BinaryLike, enc: crypto.BinaryToTextEncoding): string
function sha256 (data: crypto.BinaryLike, enc?: crypto.BinaryToTextEncoding): Buffer | string {
  const hash = crypto.createHash('sha256').update(data)
  return enc === undefined ? hash.digest() : hash.digest(enc)
}

export function concatSha256 (a: crypto.BinaryLike, b: crypto.BinaryLike): Buffer
export function concatSha256 (a: crypto.BinaryLike, b: crypto.BinaryLike, enc: crypto.BinaryToTextEncoding): string
export function concatSha256 (a: crypto.BinaryLike, b: crypto.BinaryLike, enc?: crypto.BinaryToTextEncoding): Buffer | string {
  const hash = crypto.createHash('sha256').update(a).update(b)
  return enc === undefined ? hash.digest() : hash.digest(enc)
}

export function getSealHeaderHash <Obj extends HeaderProps> (object: Obj): string {
  return hashHeader(getSealHeader(object))
}

function getMerkleRoot (tree: Pick<TradleTree, 'roots'>): Buffer {
  const [node] = tree.roots
  if (node == null) {
    throw new Error('No root found in tree.')
  }
  return node.hash
}

function computeMerkleRoot (obj: Unsigned, opts?: Partial<MerkleOpts>): Buffer {
  const tree = createMerkleTree(obj, getMerkleOpts(opts))
  return getMerkleRoot(tree)
}

const headerHashFn = sha256

function toMerkleRoot (merkleRoot: Buffer): Buffer
function toMerkleRoot (merkleRootOrObj: Unsigned, opts?: Partial<MerkleOpts>): Buffer
function toMerkleRoot (merkleRootOrObj: Buffer | Unsigned, opts?: Partial<MerkleOpts>): Buffer {
  return Buffer.isBuffer(merkleRootOrObj)
    ? merkleRootOrObj
    : computeMerkleRoot(removeHeader(merkleRootOrObj), opts)
}

function registerProtocol (obj: Partial<ProtocolRegistered>): asserts obj is ProtocolRegistered {
  const version = obj[PROTOCOL_VERSION]
  if (version === null || version === undefined) {
    obj[PROTOCOL_VERSION] = VERSION_BEFORE_PROTOCOL_VERSION_PROP
  }
}

function registerTimestamp (obj: Partial<Timestamped>): asserts obj is Timestamped {
  const timestamp = obj[TIMESTAMP]
  if (timestamp === null || timestamp === undefined) {
    obj[TIMESTAMP] = Date.now()
  }
}

export function createObject <Obj extends types.Flexible<Permalinked>> (opts: EntireObjectInput<Obj>): CreatedObject<Obj> {
  types.entireCreateObjectInput(opts, true)

  // shallow copy not too safe
  const obj = removeHeader(opts.object)
  if (opts.prev != null) {
    (obj as any)[PREVLINK] = getLink(opts.prev)
  }

  if (opts.orig != null) {
    (obj as any)[PERMALINK] = getLink(opts.orig)
  }

  types.ensureCorrectlyPermalinked(obj as Partial<Permalinked>)
  registerProtocol(obj as Partial<ProtocolRegistered>)
  registerTimestamp(obj as Partial<Timestamped>)

  return obj as CreatedObject<Obj>
}

export function nextVersion <Obj extends Signed & types.Flexible<Permalinked>> (
  object: Obj, link: string
): HeaderLess<Obj> & Permalinked & Timestamped {
  const scaffold = scaffoldNextVersion(object, { link, permalink: undefined })
  const clean = removeHeader(object)
  return Object.assign(clean, scaffold)
}

export function scaffoldNextVersion (object: Signed & types.Flexible<Permalinked>, links: Omit<LinkWrapper, 'object'>): Permalinked & Timestamped {
  const { link, permalink } = getLinks({ object, ...links })
  const headerHash = getSealHeaderHash(object)
  return {
    [PREVLINK]: link,
    [PERMALINK]: permalink,
    [PREVHEADER]: headerHash,
    [VERSION]: (object[VERSION] ?? 0) + 1,
    [TIMESTAMP]: Date.now()
  }
}

interface SignResult <Obj extends SignObject> {
  tree: IndexedTree<HeaderLess<Obj>>
  merkleRoot: Buffer
  sig: string
  object: Obj & Signed
}

async function _signAsWitness <Obj extends Signed & Signable & Partial<Witnessed>> (
  opts: { object: Obj, permalink: string, author: Author }
): Promise<Obj & Witnessed> {
  const { object, permalink } = opts
  types.ensureSigned(object)
  if (permalink === null || permalink === undefined) {
    throw new InvalidInput('expected string "permalink" of signer\'s identity')
  }

  const unsigned: SignObject = removeHeader(object) as SignObject
  const result = await promises.sign({
    ...opts,
    object: unsigned
  })

  const witnesses = types.isWitnessed(object) ? object[WITNESSES] : []
  witnesses.push({
    a: permalink,
    s: result.sig
  })
  return {
    ...object,
    [WITNESSES]: witnesses
  }
}

export const promises = Object.freeze({
  async sign <Obj extends SignObject>(opts: SignOpts<Obj> & Partial<MerkleOpts>): Promise<SignResult<Obj>> {
    types.ensureSignObjectOpts<Obj>(opts)

    const { author, object } = opts

    const tree = createMerkleTree(
      removeHeader(object),
      getMerkleOpts(opts as Partial<MerkleOpts>)
    )
    const merkleRoot = getMerkleRoot(tree)
    const sig = await promises.signMerkleRoot({ author, merkleRoot })

    return {
      tree,
      merkleRoot,
      sig,
      object: {
        ...object,
        [SIG]: sig
      }
    }
  },

  async signMerkleRoot (opts: SignMerkleOpts): Promise<string> {
    types.ensureSignMerkleOpts(opts)

    const { author, merkleRoot } = opts
    const sig = await new Promise<Buffer>((resolve, reject) => author.sign(merkleRoot, (err, sig) => (err != null) ? reject(err) : resolve(sig as Buffer)))
    const encodedSig = utils.encodeSig({
      pubKey: author.sigPubKey,
      sig: sig
    })
    return utils.sigToString(encodedSig)
  },

  signAsWitness: _signAsWitness,
  witness: _signAsWitness
})

function toCallback <Args extends any[], Response> (fn: (...args: Args) => Promise<Response>): (...args: [...Args, Callback<Response>]) => void {
  return (...args): void => {
    const cb = args.pop() as Callback<Response>
    if (typeof cb !== 'function') {
      throw new Error('Callback function expected.')
    }
    fn(...(args as unknown as Args)).then(res => cb(null, res), cb)
  }
}

export const async = Object.freeze({
  /**
   * @deprecated use .promises.sign(...)
   */
  sign: toCallback(promises.sign),
  /**
   * @deprecated use .promises.signMerkleRoot(...)
   */
  signMerkleRoot: toCallback(promises.signMerkleRoot),
  /**
   * @deprecated use .promises.signAsWitness(...)
   */
  signAsWitness: toCallback(_signAsWitness),
  /**
   * @deprecated use .promises.signAsWitness(...)
   */
  witness: toCallback(_signAsWitness)
})

/**
 * calculate a public key that seals `link` based on `basePubKey`
 */
function calcSealPubKey (opts: CalcSealOpts): PublicKey {
  types.ensureCalcSealOpts(opts)

  const headerHash = 'headerHash' in opts ? opts.headerHash : hashHeader(getSealHeader(opts.object))
  return utils.publicKeyCombine([
    opts.basePubKey,
    pubKeyFromHeaderHash(headerHash)
  ])
}

function calcSealPrevPubKey (opts: CalcSealPrevOpts): PublicKey {
  types.ensureCalcSealPrevOpts(opts)

  const prevHeaderHash = 'prevHeaderHash' in opts ? opts.prevHeaderHash : opts.object[PREVHEADER]
  return utils.publicKeyCombine([
    opts.basePubKey,
    prevPubKeyFromHeaderHash(prevHeaderHash)
  ])
}

function verifySealPubKey (opts: VerifySealPubKeyOpts): boolean {
  types.ensureVerifySealPubKeyOpts(opts)

  const { object } = opts

  const expected = utils.publicKeyCombine([
    opts.basePubKey,
    pubKeyFromObject(object)
  ])

  return utils.ecPubKeysAreEqual(expected, opts.sealPubKey)
}

function verifySealPrevPubKey (opts: VerifySealPrevPubKeyOpts): boolean {
  types.ensureVerifySealPrevPubKeySeal(opts)

  const expected = calcSealPrevPubKey(opts)
  return utils.ecPubKeysAreEqual(expected, opts.sealPrevPubKey)
}

export function parseObject <Obj extends Signed> (opts: Partial<MerkleOpts> & { object: Obj }): {
  merkleRoot: Buffer
  body: HeaderLess<Obj>
  sig: Buffer
  pubKey: PublicKey
} {
  const object = opts.object
  const body = removeHeader(object)
  const parsedSig = utils.decodeSig(object[SIG])
  return {
    merkleRoot: computeMerkleRoot(body, getMerkleOpts(opts)),
    body: body,
    sig: parsedSig.sig,
    pubKey: parsedSig.pubKey
  }
}

function getSigKey (opts: GetSigKeyOpts): PublicKey | undefined {
  types.ensureGetSigKeyOpts(opts)
  const { object, verify } = opts
  // necessary step to make sure key encoded
  // in signature is that key used to sign
  const merkleRoot = toMerkleRoot(object, opts)
  return utils.getSigKey(merkleRoot, object[SIG], verify)
}

export function verifyWitnesses (opts: { object: Partial<Witnessed>, verify?: VerifyFn }): boolean {
  const { object, verify } = opts
  return getWitnesses(object).every(witnessed => {
    return verifySig({ object: witnessed, verify })
  })
}

export function fromWitness <Obj> ({ object, witness }: { object: Obj, witness: Witness }): HeaderLess<Obj> & Signed {
  types.ensureWitness(witness)
  return Object.assign(
    removeHeader(object),
    { [SIG]: witness.s }
  )
}

export const verifyWitness = ({ object, witness, verify }: GetSigKeyOpts & { witness: Witness }): boolean => verifySig({
  object: fromWitness({ object, witness }),
  verify
})

function getWitnesses (object: Partial<Witnessed>): Array<
types.HeaderLess<Partial<Witnessed>> & Signed
> {
  const witnesses = object[WITNESSES]
  if (notExists(witnesses)) return []

  return witnesses.map(witness => fromWitness({ object, witness }))
}

export function verifySig (opts: GetSigKeyOpts): boolean {
  try {
    return !(getSigKey(opts) == null)
  } catch (err) {
    return false
  }
}

function validatePrevVersioning (
  object: Timestamped & Partial<Permalinked>,
  prev?: Signed & Timestamped & Partial<Permalinked>
): void {
  const { [PREVLINK]: prevLink, [PREVHEADER]: prevHeader, [PERMALINK]: permalink } = object
  if (notExists(prev)) {
    throw new InvalidInput('expected "prev"')
  }
  if (notExists(prevLink)) {
    throw new InvalidInput(`expected object.${PREVLINK}`)
  }
  // TODO: this is unnecessary, ensureTimestampIncreased is no assertion!
  //       It should probably check if the time really increased
  types.ensureTimestampIncreased(object, prev)
  const checkPrevLink = getLink(prev)
  if (prevLink !== checkPrevLink) {
    throw new InvalidInput(`object.${PREVLINK} and "prev" don't match (${prevLink} != ${checkPrevLink})`)
  }
  if (notExists(prevHeader)) {
    throw new InvalidInput(`expected object.${PREVHEADER} to be set.`)
  }
  const checkHeader = getSealHeaderHash(prev)
  if (prevHeader !== checkHeader) {
    throw new InvalidInput(`expected object.${PREVHEADER} to equal the header hash of "prev" (${prevHeader} != ${checkHeader})`)
  }
  const prevPermalink = prev[PERMALINK]
  if (exists(prevPermalink) && prevPermalink !== permalink) {
    throw new InvalidInput(`expected object.${PERMALINK} (${String(permalink)}) === prev.${PERMALINK} (${prevPermalink})`)
  }
}

function validateOrigVersioning (
  object: Partial<Permalinked> & Timestamped,
  orig?: string | Signed | Buffer
): void {
  const { [PERMALINK]: permalink } = object
  if (notExists(permalink)) {
    throw new InvalidInput(`expected object.${PERMALINK}`)
  }
  if (notExists(orig)) {
    throw new InvalidInput('expected "orig"')
  }
  const expectedOrig = typeof orig === 'string' ? orig : getLink(orig)
  if (permalink !== expectedOrig) {
    throw new InvalidInput(`expected object.${PERMALINK} (${permalink}) === orig (${expectedOrig})`)
  }
}

/**
 * validate object sequence
 */
export function validateVersioning (opts: {
  object: Timestamped & Partial<Versionable>
  orig?: string | Signed | Buffer
  prev?: Signed & Timestamped & Partial<Permalinked>
}): void {
  const { object, prev, orig } = opts
  const expectsZero = !(exists(object[PREVLINK]) || exists(prev) || exists(object[PERMALINK]) || exists(orig))
  const isZero = notExists(object[VERSION]) || object[VERSION] === 0
  if (isZero) {
    if (!expectsZero) {
      throw new Errors.InvalidVersion(`expected object.${VERSION} to be non-zero (is ${String(object[VERSION])}) with prev/orig present.`)
    }
  } else {
    if (expectsZero) {
      throw new InvalidVersion(`expected object.${VERSION} to be 0 if neither object.${PREVLINK} nor object.${PERMALINK} is set.`)
    }
    validatePrevVersioning(object, prev)
    validateOrigVersioning(object, orig)
  }
}

export function preProcessForMerklization <Obj extends Partial<ProtocolRegistered>> (obj: Obj, merkleOpts?: Partial<MerkleOpts>): Obj {
  const protocolVersion = obj[PROTOCOL_VERSION] ?? VERSION_BEFORE_PROTOCOL_VERSION_PROP
  const major = getSemverMajor(protocolVersion)
  if (major > 4) {
    obj = cloneDeep(obj)
    return normalizeEmbeddedMedia(obj, merkleOpts)
  }
  return obj
}

function normalizeEmbeddedMedia (obj: any, merkleOpts?: Partial<MerkleOpts>): any {
  const merkleOpts2 = getMerkleOpts(merkleOpts)
  const getHashHex = (data: DataURI): string => merkleOpts2.leaf({ data, index: 0, parent: 0, size: data.length }, []).toString('hex')

  traverse(obj).forEach(function (value) {
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

const arrayOfBuffer: Check<Buffer[]> = typeforce.arrayOf(typeforce.Buffer)

export function merkleTreeFromHashes (hashes: Buffer[], opts?: Partial<MerkleOpts>): types.TradleTree & {
  root: Buffer
} {
  arrayOfBuffer.assert(hashes)
  const gen = new MerkleGenerator(getMerkleOpts(opts))
  const nodes: Array<Node<Buffer>> = []
  for (const hash of hashes) {
    gen.next(hash, nodes)
  }
  gen.next(MerkleGenerator.CLOSE_UP, nodes)
  return {
    nodes,
    roots: gen.roots,
    root: getMerkleRoot(gen)
  }
}

function createMerkleTree <Obj extends Unsigned & Partial<ProtocolRegistered>> (obj: Obj, opts?: Partial<MerkleOpts>): IndexedTree<Obj> {
  types.ensureUnsigned(obj)

  const merkleOpts = getMerkleOpts(opts)
  const gen = new MerkleGenerator(merkleOpts)

  const processed = preProcessForMerklization(obj, merkleOpts)

  // list with flat-tree indices
  const nodes: Array<Node<Buffer>> = []
  const keys = getKeysSorted(obj)
  for (const key of keys) {
    gen.next(stringify(key), nodes)
    gen.next(stringify(processed[key]), nodes)
  }

  gen.next(MerkleGenerator.CLOSE_UP, nodes)
  return {
    nodes: nodes.sort(byIndexSort),
    roots: gen.roots,
    indices: getIndices(obj, keys)
  }
}

export function prover <Obj extends Unsigned> (object: Obj, opts?: Partial<MerkleOpts>): Prover<Obj> {
  const tree = createMerkleTree(object, getMerkleOpts(opts))
  const leaves: TradleLeaf[] = []
  const builder = {
    add (opts: ProofEntry<Obj>) {
      types.ensureProofEntry.assert(opts, true)

      const prop = opts.property
      const propNodes: TreeIndex = (tree.indices as any)[prop]
      if (ok(opts.key)) leaves.push(tree.nodes[propNodes.key] as TradleLeaf)
      if (ok(opts.value)) leaves.push(tree.nodes[propNodes.value] as TradleLeaf)

      return builder
    },
    leaves () {
      return leaves.slice()
    },
    proof () {
      return prove({
        nodes: tree.nodes,
        leaves: leaves
      })
    }
  }

  return builder
}

export function prove (opts: Provable): Array<MiniNode<Buffer>> {
  // return nodes needed to prove leaves at leafIndices are part of the tree
  types.ensureProvable(opts)

  const prover = new MerkleProofGenerator<Buffer, MiniNode<Buffer>>(opts.nodes)
  for (const leaf of opts.leaves) {
    prover.add(leaf)
  }

  return prover.proof()
}

export function verifyProof (opts: Verifiable & Partial<MerkleOpts>): boolean {
  types.ensureVerifiable.assert(opts)

  const verify = createVerifier<Buffer>(
    getMerkleVerifierOpts({ proof: opts.proof }) as any
  )
  return verify(opts.node)
}

function alphabetical (a: string, b: string): 0 | -1 | 1 {
  const al = a.toLowerCase()
  const bl = b.toLowerCase()
  return al < bl ? -1 : al > bl ? 1 : 0
}

function byIndexSort (a: { index: number }, b: { index: number }): number {
  return a.index - b.index
}

function getMerkleOpts <Opts extends types.Flexible<MerkleOpts>> (opts?: Opts): Opts & MerkleOpts {
  /* eslint-disable-next-line @typescript-eslint/consistent-type-assertions */
  return {
    ...DEFAULT_MERKLE_OPTS,
    ...opts
  } as Opts & MerkleOpts
}

function getMerkleVerifierOpts <Opts extends types.Flexible<MerkleOpts>> (opts?: Opts): Opts & MerkleOpts {
  /* eslint-disable-next-line @typescript-eslint/consistent-type-assertions */
  return {
    ...DEFAULT_MERKLE_OPTS,
    ...opts
  } as Opts & MerkleVerifierOpts<Buffer>
}

const getLeaves = <T extends { index: number }>(nodes: T[]): T[] => nodes.filter(n => n.index % 2 === 0)

function getKeysSorted <T extends Object> (obj: T): Array<types.StringKeys<T>> {
  // Note: this should NOT be StringKeys but for simplicity's sake and to compile
  //       it has become StringKeys.
  return Object.keys(obj).sort(alphabetical) as Array<types.StringKeys<T>>
}

function getIndices <
  Obj extends Object,
  Keys extends Array<types.StringKeys<Obj>> = Array<types.StringKeys<Obj>>
> (
  obj: Obj,
  keys?: Keys
): Indices<Obj, Keys> {
  // Note: Typescript hacks in here are uncomfortable
  const finalKeys: Array<types.ArrayType<Keys>> = (keys ?? getKeysSorted(obj)) as any
  const indices: { [key in types.ArrayType<Keys>]: TreeIndex } = {} as any
  let i = 0
  for (const key of finalKeys) {
    indices[key] = {
      key: flatTree.index(0, i),
      value: flatTree.index(0, i + 1)
    }
    i += 2
  }

  return indices as any
}

function toPrivateKey (priv: string | Buffer): Buffer {
  if (typeof priv === 'string') {
    priv = toBuffer(priv)
  }

  if (priv.length !== 32) {
    priv = sha256(priv)
  }

  // TODO: shouldn't this be inside the previous if?
  while (!secp256k1.privateKeyVerify(priv)) {
    priv = sha256(priv)
  }

  return priv
}

function getHeader <Input extends Signed, Output extends Signed> (obj: Input, props: Array<keyof Input>): Signed & Partial<Output> {
  types.ensureSigned(obj)
  const header = pick(obj, props)
  for (const p in header) {
    const val = header[p]
    // TODO:
    if (Buffer.isBuffer(val)) {
      header[p] = val.toString('base64') as any
    }
  }

  return header as unknown as Output
}
function getSealHeader <Obj extends Signed> (obj: Obj): Signed & Partial<HeaderProps> {
  return getHeader<HeaderInput, HeaderProps>(obj, HEADER_PROPS)
}

function getLinkHeader <Obj extends Signed> (obj: Obj): Signed & Partial<LinkHeaderProps> {
  return getHeader<LinkHeaderProps, LinkHeaderProps>(obj, LINK_HEADER_PROPS)
}

const removeHeader = <T extends Object> (obj: T): HeaderLess<T> => omit(obj, HEADER_PROPS) as HeaderLess<T>

function getLink (obj: Buffer | string | Signed): string
function getLink (obj: Buffer | string | Signed, enc: undefined): Buffer
function getLink (obj: Buffer | string | Signed, enc: crypto.BinaryToTextEncoding): string
function getLink (obj: Buffer | string | Signed, enc: crypto.BinaryToTextEncoding | undefined = ENC): Buffer | string {
  let signed: Partial<Signed>
  if (Buffer.isBuffer(obj)) {
    if (obj.length === 32) {
      return exists(enc) ? obj.toString(enc) : obj
    }
    signed = JSON.parse(obj.toString(enc))
  } else if (typeof obj === 'string') {
    signed = JSON.parse(obj)
  } else {
    signed = obj
  }
  types.ensureSigned(signed)

  return hashHeader(getLinkHeader(signed), enc)
}

/**
 * @deprecated use .getLink
 */
const getStringLink = getLink

type Links <T extends LinkWrapper> =
(
  T extends LinkWrapper<string> | LinkWrapper<any, Signed & Partial<Permalinked>>
    ? {
        link: string
      }
    : {}
) &
(
  T extends LinkWrapper<any, any, string> | LinkWrapper<any, Signed & Partial<Permalinked>> | LinkWrapper<any, any, string>
    ? {
        permalink: string
        prevLink: string
      }
    : {}
)

function getLinks <T extends LinkWrapper> (wrapper: T): Links<T> {
  types.ensureLinkWrapper(wrapper)

  const object = wrapper.object
  const link = wrapper.link ?? ((object != null) ? getLink(object) : undefined)
  const links = {
    link,
    permalink: wrapper.permalink ?? (exists(object) ? (object[PERMALINK] ?? link) : undefined),
    prevLink: wrapper.prevLink ?? (exists(object) ? object[PREVLINK] : undefined)
  }

  if (exists(links.prevLink)) {
    if (notExists(links.permalink)) {
      throw new InvalidInput('expected "permalink"')
    }
    return links as Links<T>
  }

  if (exists(link)) {
    return { link } as unknown as Links<T>
  }
  /* eslint-disable-next-line @typescript-eslint/consistent-type-assertions */
  return {} as Links<T>
}

function pubKeyFromObject (object: HeaderProps): PublicKey {
  return pubKeyFromHeaderHash(hashHeader(getSealHeader(object), ENC))
}

function hashHeader (header: any, enc: crypto.BinaryToTextEncoding = ENC): string {
  return headerHashFn(stringify(header), enc)
}

function prevPubKeyFromHeaderHash (headerHash: string | Buffer, enc: crypto.BinaryToTextEncoding = ENC): PublicKey {
  return pubKeyFromHeaderHash(iterateHeaderHash(headerHash, enc))
}

export function iterateHeaderHash (headerHash: string | Buffer, enc: crypto.BinaryToTextEncoding = ENC): string {
  return headerHashFn(toBuffer(headerHash, enc), enc)
}

function getIteratedHeaderHash <Obj extends HeaderProps> (object: Obj): string {
  return iterateHeaderHash(getSealHeaderHash(object))
}

function toBuffer (input: string | Buffer, enc: BufferEncoding = ENC): Buffer {
  return Buffer.isBuffer(input) ? input : Buffer.from(input, enc)
}

function pubKeyFromHeaderHash (hash: string | Buffer): PublicKey {
  return privToPub(toPrivateKey(hash))
}

function privToPub (priv: Uint8Array): PublicKey {
  return {
    curve: CURVE,
    pub: Buffer.from(secp256k1.publicKeyCreate(priv, false))
  }
}

export const DEFAULT_MERKLE_OPTS: MerkleOpts = {
  leaf: (node) => sha256(node.data),
  parent: (a, b) => concatSha256(a.hash, b.hash)
}

export function wrapWitnessSig (opts: WitnessUnwrapped): Witness {
  types.ensureWitness(opts)
  return {
    a: opts.author,
    s: opts.sig
  }
}

export function unwrapWitnessSig (opts: Witness): WitnessUnwrapped {
  types.ensureWitness(opts)
  return {
    author: opts.a,
    sig: opts.s
  }
}

export const protobufs = { schema }
export { genECKey } from './lib/utils'

const { sign, signMerkleRoot, signAsWitness, witness } = async

export {
  CURRENT_PROTOCOL_VERSION as version,
  sha256 as merkleHash,
  createMerkleTree as tree,
  computeMerkleRoot as merkleRoot,
  createObject as object,
  calcSealPubKey as sealPubKey,
  calcSealPrevPubKey as sealPrevPubKey,
  verifySealPubKey,
  verifySealPrevPubKey,
  sign,
  signMerkleRoot,
  signAsWitness,
  witness,
  getSigKey as sigPubKey,
  verifySig as verify,
  getLeaves as leaves,
  getIndices as indices,
  getStringLink as linkString,
  getLink as link,
  getLinks as links,
  getSealHeader as header,
  getSealHeaderHash as headerHash,
  getIteratedHeaderHash as iteratedHeaderHash,
  removeHeader as body,
  secp256k1,
  types,
  schema,
  stringify,
  constants,
  utils,
  Errors
}
