import * as typeforce from '@tradle/typeforce'
import type { Raw, TypeForCheck } from '@tradle/typeforce/src/interfaces'
import * as traverse from 'traverse'
import constants = require('@tradle/constants')
import type {
  SignedObject,
  Message,
  Signed,
  Unsigned,
  Typed,
  Timestamped,
  Versioned,
  Permalinked,
  NotPermalinked,
  CorrectlyPermalinked,
  ProcessedObject,
  PublicKey,
  Author,
  Signable,
  SignObject,
  RawObject,
  Witnessed,
  ProtocolRegistered,
  Authored,
  Recipient,
  PrivateKey,
  Key
} from '@tradle/constants/types'
import * as Errors from './errors'
import { AssertCheck, MatchCheck, Check } from '@tradle/typeforce/src/interfaces'
import { Leaf, MerkleGeneratorOpts, Node } from '@tradle/merkle-tree-stream/types'
import { HEADER_PROPS } from './constants'
import { exists, notExists } from './utils'

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
  TYPES,
  WITNESSES
} = constants

const { IDENTITY } = TYPES

export interface KeyObj {
  pub: Buffer
  priv: Buffer
}

export interface Witness {
  a: string
  s: string
}

export interface EntireObjectInput <Obj extends Object> {
  object: Obj
  prev?: ProcessedObject
  orig?: Signed | Buffer
}

export type TradleNode = Pick<Node<Buffer>, 'hash' | 'index'>
export type TradleLeaf = Pick<Leaf<Buffer>, 'hash' | 'index' | 'data'>
export interface TradleTree {
  nodes: TradleNode[]
  roots: TradleNode[]
}

export const merkleNode: AssertCheck<TradleNode> = typeforce.object({
  hash: typeforce.Buffer,
  index: typeforce.Number
})

export const merkleLeaf: AssertCheck<TradleLeaf> = typeforce.object({
  data: typeforce.Buffer,
  hash: typeforce.Buffer,
  index: typeforce.Number
})

export const merkleTree: AssertCheck<TradleTree> = typeforce.object({
  nodes: typeforce.arrayOf(merkleLeaf),
  roots: typeforce.arrayOf(merkleNode)
})

export const keyObj: MatchCheck<KeyObj> = typeforce.addAPI(function KeyObj (val: any): val is KeyObj {
  return exists(val) && (Buffer.isBuffer(val.pub) || Buffer.isBuffer(val.priv))
})

export const merkleRootOrObj = typeforce.anyOf(ensureSigned, typeforce.Buffer)

export const ecPubKey: AssertCheck<PublicKey> = typeforce.object({
  pub: typeforce.Buffer,
  curve: typeforce.String
})

export const ecPrivKey: AssertCheck<PrivateKey> = typeforce.object({
  priv: typeforce.Buffer,
  curve: typeforce.String
})

export const ecKey: AssertCheck<Key> = typeforce.object({
  pub: typeforce.Buffer,
  priv: typeforce.Buffer,
  curve: typeforce.String
})

export const chainPubKey: MatchCheck<PublicKey> = typeforce.addAPI(function ChainPubKey (key: PublicKey): key is PublicKey {
  return Buffer.isBuffer(key.pub) && key.curve === 'secp256k1'
})

export const author: AssertCheck<Author> = typeforce.object({
  sigPubKey: ecPubKey,
  sign: typeforce.Function,
  permalink: typeforce.maybe(typeforce.String)
}) as AssertCheck<Author>

export const recipient: AssertCheck<Recipient> = typeforce.object({
  pubKey: ecPubKey,
  link: typeforce.String
})

const ensureRequiredProps: AssertCheck<Signable> = typeforce.addAPI((obj: {}): asserts obj is Signable => {
  ensureRequiredPropsPreSign(obj)
  ensureAuthor(obj)

  // @ts-expect-error
  return true
})

export const object: AssertCheck<Signable> = ensureRequiredProps

export function createObjectInput (val: {}): asserts val is Unsigned & Typed {
  ensureUnsigned(val)
  ensureRequiredPropsBase(val)

  // @ts-expect-error
  return true
}

export const entireCreateObjectInput: AssertCheck<EntireObjectInput<any>> = typeforce.object({
  object: createObjectInput,
  prev: maybeDefined(signedObject),
  orig: maybeDefined(merkleRootOrObj)
})

export function signObjectInput (val: any): asserts val is SignObject {
  ensureUnsigned(val)
  ensureRequiredPropsPreSign(val)

  // @ts-expect-error
  return true
}

export interface SignOpts<Obj extends SignObject = SignObject> {
  author: Author
  object: Obj
}

export const ensureSignObjectOpts: <Obj extends SignObject = SignObject> (val: any) => asserts val is SignOpts<Obj> = typeforce.object({
  author,
  object: signObjectInput
})

export function rawObject (val: any): asserts val is RawObject {
  ensureUnsigned(val)
  ensureRequiredProps(val)
  ensureCorrectlyPermalinked(val)

  // @ts-expect-error
  return true
}

export function signedObject (val: any): asserts val is SignedObject {
  ensureSigned(val)
  ensureRequiredProps(val)
  ensureCorrectlyPermalinked(val)

  // @ts-expect-error
  return true
}

export const linkOrObject: Check<string | SignedObject> = typeforce.anyOf(typeforce.String, signedObject)

export const messageBody: AssertCheck<Message> = typeforce.object({
  object: signedObject,
  [RECIPIENT]: typeforce.String,
  [SEQ]: maybeDefined(typeforce.Number),
  [PREV_TO_RECIPIENT]: maybeDefined(linkOrObject)
})

export const witness: AssertCheck<Witness> = typeforce.object({
  a: typeforce.String,
  s: typeforce.String
})

export function ensureSigned (obj: Partial<Signed>): asserts obj is Signed {
  if (typeof obj[SIG] !== 'string') {
    throw new Errors.InvalidProperty(SIG, 'expected signed object')
  }
  // @ts-expect-error
  return true
}

export function ensureUnsigned (obj: Partial<Unsigned>): asserts obj is Unsigned {
  if (SIG in obj) throw new Errors.InvalidProperty(SIG, 'expected unsigned object')
  // @ts-expect-error
  return true
}

export function ensureTyped (obj: Partial<Typed>): asserts obj is Typed {
  if (typeof obj[TYPE] !== 'string') throw new Errors.InvalidProperty(TYPE, `expected string ${TYPE}`)
  // @ts-expect-error
  return true
}

export function ensureTimestamp (obj: Partial<Timestamped>): asserts obj is Timestamped {
  if (typeof obj[TIMESTAMP] !== 'number') throw new Errors.InvalidProperty(TIMESTAMP, `expected number ${TIMESTAMP}`)
  // @ts-expect-error
  return true
}

export function ensureTimestampIncreased (object: Timestamped, prev: Timestamped): boolean {
  return object[TIMESTAMP] > prev[TIMESTAMP]
}

export function ensureNonZeroVersion (object: Versioned): boolean {
  if (!(object[VERSION] > 0)) {
    throw new Errors.InvalidVersion(`expected non-zero version ${VERSION}`)
  }
  return true
}

export function isPermalinked (obj: Partial<Permalinked>): obj is Permalinked {
  return PERMALINK in obj &&
    typeof obj[PERMALINK] === 'string' &&
    typeof obj[PREVLINK] === 'string' &&
    typeof obj[PREVHEADER] === 'string' &&
    (obj[VERSION] ?? 0) > 0
}

export function isWitnessed (obj: Partial<Witnessed>): obj is Witnessed {
  return WITNESSES in obj && Array.isArray(obj[WITNESSES])
}

export function isNotPermalinked (obj: Partial<Permalinked>): obj is NotPermalinked {
  return obj[PREVLINK] === undefined &&
    obj[PREVHEADER] === undefined &&
    (obj[VERSION] === undefined || obj[VERSION] === 0)
}

export function isCorrectlyPermalinked (obj: Partial<Permalinked>): obj is CorrectlyPermalinked {
  // both or neither must be present
  if (isPermalinked(obj)) {
    return true
  }
  if (isNotPermalinked(obj)) {
    return true
  }
  return false
}

export function ensureCorrectlyPermalinked (obj: Partial<Permalinked>): asserts obj is CorrectlyPermalinked {
  if (!isCorrectlyPermalinked(obj)) {
    throw new Errors.InvalidVersion(
      `expected either ${PERMALINK}, ${PREVLINK} and ${VERSION} > 0, or neither, and ${VERSION} === 0`
    )
  }
  // @ts-expect-error
  return true
}

/**
 * @deprecated use .ensureCorrectlyPermalinked
 */
export const ensureVersionProps: (obj: Partial<Permalinked>) => asserts obj is CorrectlyPermalinked = ensureCorrectlyPermalinked

function findPathWithUndefinedVal (obj: Object): string | undefined {
  let bad: string | undefined
  traverse(obj).forEach(function (val) {
    if (val === undefined) {
      bad = this.path.join('.')
      this.stop()
    }
  })
  return bad
}

function ensureAuthor (obj: Partial<Typed> & Partial<Authored> & Partial<Versioned>): void {
  if (obj[TYPE] === IDENTITY && notExists(obj[VERSION])) {
    if (exists(obj[AUTHOR])) {
      throw new Errors.InvalidInput(`unexpected property ${AUTHOR}`)
    }
  } else {
    if (notExists(obj[AUTHOR])) {
      throw new Errors.InvalidInput(`expected property ${AUTHOR}`)
    }
  }
}

function ensureRequiredPropsPreSign (obj: Partial<Signable>): asserts obj is Signable {
  ensureRequiredPropsBase(obj)
  ensureCorrectlyPermalinked(obj as Partial<Permalinked>)
  ensureTimestamp(obj as Partial<Timestamped>)

  // @ts-expect-error
  return true
}

function ensureRequiredPropsBase (obj: any): asserts obj is Typed {
  ensureTyped(obj)
  const bad = findPathWithUndefinedVal(obj)
  if (bad !== undefined) {
    throw new Errors.InvalidProperty(bad, 'must not have "undefined" values')
  }

  // @ts-expect-error
  return true
}

export interface Provable {
  nodes: TradleNode[]
  leaves: TradleLeaf[]
}

export const ensureProvable: AssertCheck<Provable> = typeforce.object({
  nodes: typeforce.arrayOf(merkleNode),
  leaves: typeforce.arrayOf(merkleLeaf)
})

export interface Verifiable {
  proof: TradleNode[]
  node: TradleLeaf
}

export const ensureVerifiable: AssertCheck<Verifiable> = typeforce.object({
  proof: typeforce.arrayOf(merkleNode),
  node: merkleLeaf
})

export interface ProofEntry <Obj> {
  property: StringKeys<Obj>
  key?: boolean
  value?: boolean
}

export interface Prover <Obj> {
  add: (opts: ProofEntry<Obj>) => this
  leaves: () => any[]
  proof: () => any[]
}

export interface MerkleOpts extends MerkleGeneratorOpts<Buffer> {}

export interface GetSigKeyOpts extends Partial<MerkleOpts> {
  object: Signed
  verify?: VerifyFn
}

export interface Callback <T> {
  (err: Error): any
  (err: null, obj: T): any
  (err: Error | null, obj: T | undefined): any
}

function maybeDefined <T extends Raw> (type: T): Check<TypeForCheck<T> | undefined> {
  return typeforce.addAPI((value: T | undefined, strict?: boolean): boolean => {
    return value === undefined || type(value, strict)
  }) as Check<TypeForCheck<T> | undefined>
}

export const ensureProofEntry: AssertCheck<ProofEntry<any>> = typeforce.object({
  property: typeforce.String,
  key: maybeDefined(typeforce.Boolean),
  value: maybeDefined(typeforce.Boolean)
})

export interface WitnessUnwrapped {
  author: string
  sig: string
}

export const ensureWitnessUnwrapped: AssertCheck<WitnessUnwrapped> = typeforce.object({
  author: typeforce.String,
  sig: typeforce.String
})

export const ensureWitness: AssertCheck<Witness> = typeforce.object({
  a: typeforce.String,
  s: typeforce.String
})

export interface SignMerkleOpts {
  author: Author
  merkleRoot: Buffer
}

export const ensureSignMerkleOpts: AssertCheck<SignMerkleOpts> = typeforce.object({
  author,
  merkleRoot: typeforce.Buffer
})

export interface AnyCalcSealOpts {
  basePubKey: PublicKey
}
export interface CalcSealByObject extends AnyCalcSealOpts {
  object: Signed
}
export interface CalcSealByHeaderHash extends AnyCalcSealOpts {
  headerHash: string
}
export interface CalcSealByPrevLinked extends AnyCalcSealOpts {
  object: Signed & Permalinked
}
export interface CalcSealByPrevHeaderHash extends AnyCalcSealOpts {
  prevHeaderHash: string
}
export type CalcSealOpts = CalcSealByObject | CalcSealByHeaderHash

export const ensureCalcSealOpts: AssertCheck<CalcSealOpts> = typeforce.allOf(
  { basePubKey: chainPubKey },
  typeforce.anyOf(
    { object: ensureSigned },
    { headerHash: typeforce.String }
  )
)

export type CalcSealPrevOpts = CalcSealByPrevLinked | CalcSealByPrevHeaderHash

export const ensureCalcSealPrevOpts: AssertCheck<CalcSealPrevOpts> = typeforce.allOf(
  { basePubKey: chainPubKey },
  typeforce.anyOf(
    { object: typeforce.allOf(ensureSigned, isPermalinked) },
    { prevHeaderHash: typeforce.String }
  )
)

export interface VerifySealPubKeyOpts {
  object: Signed
  basePubKey: PublicKey
  sealPubKey: PublicKey
}

export const ensureVerifySealPubKeyOpts: AssertCheck<VerifySealPubKeyOpts> = typeforce.object({
  object: ensureSigned,
  basePubKey: chainPubKey,
  sealPubKey: chainPubKey
})

export interface LinkWrapper <
  Link extends string | undefined = string | undefined,
  Object extends (Signed & Partial<Permalinked>) | undefined = (Signed & Partial<Permalinked>) | undefined,
  Permalink extends string | undefined = string | undefined
> {
  link: Link
  object: Object
  permalink: Permalink
  prevLink?: string
}

export const ensureLinkWrapper: AssertCheck<LinkWrapper> = typeforce.object({
  object: maybeDefined(signedObject),
  permalink: maybeDefined(typeforce.String),
  prevLink: maybeDefined(typeforce.String),
  link: maybeDefined(typeforce.String)
})

export type IndexedTree <Obj, Keys extends Array<StringKeys<Obj>> = Array<StringKeys<Obj>>> = TradleTree & {
  indices: Indices<Obj, Keys>
}

export interface TreeIndex {
  key: number
  value: number
}

export type Indices <Obj extends Object, Keys extends Array<string | number | symbol> | undefined | null> =
  Keys extends undefined | null
    ? { [key in StringKeys<Obj>]: TreeIndex }
    : Keys extends string[]
      ? { [key in ArrayType<Keys>]: TreeIndex }
      : { [key: string]: TreeIndex }

export type StringKeys <T> = Extract<keyof T, string>
export type ArrayType <T extends any[]> = T extends Array<infer U> ? U : unknown
export type HeaderLess <T extends Object> = Omit<T, ArrayType<typeof HEADER_PROPS>>
export type Flexible <T> = Partial<T> & { [unknownProperty: string]: unknown }

export type CreatedObject <T extends Object> = HeaderLess<T> & Timestamped & ProtocolRegistered & CorrectlyPermalinked

export type VerifySealPrevPubKeyOpts = CalcSealPrevOpts & {
  sealPrevPubKey: PublicKey
}

export const ensureVerifySealPrevPubKeySeal: AssertCheck<{ sealPrevPubKey: PublicKey }> = typeforce.object({
  sealPrevPubKey: chainPubKey
})

export const ensureGetSigKeyOpts: AssertCheck<GetSigKeyOpts> = typeforce.object({
  object: signedObject,
  verify: maybeDefined(typeforce.Function as MatchCheck<VerifyFn>)
})

export type VerifyFn = (key: PublicKey, msg: Uint8Array, sig: Buffer) => boolean
