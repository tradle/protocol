import * as crypto from 'crypto'
import * as secp256k1 from 'secp256k1'
import { ec as EC } from 'elliptic'
import type { Key, PrivateKey, PublicKey, Signature } from '@tradle/constants/types'
import * as schema from './schema'
import * as types from './types'

export function notExists (input: any): input is null | undefined {
  return input === null || input === undefined
}

export function exists <T> (input: T | null | undefined): input is T {
  return input !== null && input !== undefined
}

export function ok (input: any | null | undefined): boolean {
  return exists(input) && input !== false && input !== 0 && input !== ''
}

class Cache <T> {
  cache: { [key: string]: T }
  create: (key: string) => T
  constructor (create: (key: string) => T) {
    this.create = create
    this.cache = {}
  }

  getOrCreate (key: string): T {
    if (key in this.cache) {
      return this.cache[key] as T
    }
    const res = this.create(key)
    this.cache[key] = res
    return res
  }
}

const curves = new Cache(name => new EC(name))

export function curve (name: EC | string): EC {
  if (typeof name !== 'string') return name
  return curves.getOrCreate(name)
}

export function assert (statement: any, msg?: string): asserts statement is true | string | number | Object | Symbol {
  if (!ok(statement)) throw new Error(msg ?? 'Assertion failed')
}

export interface MarkedAsync <T extends any[]> {
  (...args: T): void
  _async: true
}

function isMarkedAsync (fn: Function): fn is MarkedAsync<any[]> {
  return '_async' in fn && (fn as MarkedAsync<any[]>)._async
}

const noop = function (): any {}

type Asyncified <F extends null | undefined | ((...args: any[]) => void)> =
  F extends null
    ? () => void
    : F extends undefined
      ? () => void
      : F extends MarkedAsync<any[]>
        ? F
        : F extends Function
          ? ((...ars: Parameters<F>) => void) & {
              _async: true
            }
          : unknown

function asyncifyDefined <F extends (...args: any[]) => void> (fn: F, allowMultipleCalls?: boolean): Asyncified<F> {
  const once = !ok(allowMultipleCalls)
  let called: boolean = false
  let ticked: boolean = false
  let ctx: any
  let args: any[]

  queueMicrotask(function () {
    if (args !== undefined) apply()
    else ticked = true
  })

  const asyncFn = function (this: any, ...input: any[]): void {
    ctx = this
    args = input
    if (ticked) apply()
  } as Asyncified<F>
  asyncFn._async = true
  return asyncFn

  function apply (): void {
    if (called && once) return

    called = true
    fn.apply(ctx, args)
  }
}

/**
 * This will DELAY the function call for one frame, not turn it in an async function.
 *
 * @deprecated This function is difficult to use correctly, use different concepts!
 */
export function asyncify <F extends null | undefined | ((...args: any[]) => void)> (fn: F, allowMultipleCalls?: boolean): Asyncified<F> {
  if (fn == null) return noop as Asyncified<F>
  if (isMarkedAsync(fn)) return fn as Asyncified<F>
  return asyncifyDefined(fn, allowMultipleCalls) as Asyncified<F>
}

// Used to show a deprecation warning only once
const deprecation = {
  sign: true,
  getSigKey: true
}

// TODO: use nkey
export function sign (msg: Uint8Array, key: PrivateKey): Buffer {
  if (deprecation.sign) {
    console.warn('utils.sign is deprecated, use nkey-{implementation} instead')
    deprecation.sign = false
  }
  types.ecPrivKey.assert(key)

  if (key.curve === 'secp256k1') {
    const sig = secp256k1.ecdsaSign(msg, key.priv)

    // Ensure low S value
    const normalSig = secp256k1.signatureNormalize(sig.signature)

    // Convert to DER array
    return Buffer.from(secp256k1.signatureExport(normalSig))
  } else {
    return Buffer.from(curve(key.curve).sign(msg, key.priv).toDER())
  }
}

/**
 * extract key from signature, verifying sig
 *
 * TODO: figure out why this was previously marked deprecated and what to use instead.
 *
 * @deprecated
 */
export function getSigKey (msg: Uint8Array, sig: string | Buffer, verify?: typeof defaultVerify): PublicKey | undefined {
  if (deprecation.getSigKey) {
    console.warn('utils.getSigKey is deprecated')
    deprecation.getSigKey = false
  }
  const parsed = decodeSig(sig)
  const key = parsed.pubKey
  verify ??= defaultVerify
  if (verify(key, msg, parsed.sig)) {
    return key
  }
}

export const defaultVerify: types.VerifyFn = (key: PublicKey, msg: Uint8Array, sig: Uint8Array): boolean => {
  if (key.curve === 'secp256k1') {
    sig = secp256k1.signatureImport(sig)
    return secp256k1.ecdsaVerify(msg, sig, key.pub)
  }
  return curve(key.curve).verify(msg, sig, key.pub)
}

export function publicKeyCombineArray (curves: [PublicKey, PublicKey]): PublicKey {
  return publicKeyCombineEach(curves[0], curves[1])
}

export function publicKeyCombineEach (a: PublicKey, b: PublicKey): PublicKey {
  if (a.curve !== b.curve) {
    throw new Error(`Can not combine curves, curves of different type. (${a.curve} != ${b.curve})`)
  }
  let pub: Buffer
  if (a.curve === 'secp256k1') {
    pub = Buffer.from(secp256k1.publicKeyCombine([a.pub, b.pub], false))
  } else {
    const curveImpl = curve(a.curve)
    const pubA = curveImpl.keyFromPublic(a.pub).getPublic()
    const pubB = curveImpl.keyFromPublic(b.pub).getPublic()
    pub = Buffer.from(pubA.add(pubB).encode('array', false))
  }

  return {
    curve: a.curve,
    pub
  }
}

export function publicKeyCombine (a: PublicKey, b: PublicKey): PublicKey
export function publicKeyCombine (curves: [PublicKey, PublicKey]): PublicKey
export function publicKeyCombine (a: [PublicKey, PublicKey] | PublicKey, b?: PublicKey): PublicKey {
  if (Array.isArray(a)) {
    return publicKeyCombineArray(a)
  }
  return publicKeyCombineEach(a, b as PublicKey)
}

export function ecPubKeysAreEqual (a: PublicKey, b: PublicKey): boolean {
  return a.curve === b.curve && a.pub.equals(b.pub)
}

export function sigToString (sig: string | Buffer): string {
  return typeof sig === 'string' ? sig : sig.toString('base64')
}

export function sigToBuf (sig: Buffer | string): Buffer {
  return Buffer.isBuffer(sig) ? sig : Buffer.from(sig, 'base64')
}

/**
 * @deprecated Use decodeSig
 */
export function parseSig (sig: Buffer | string): Signature {
  return decodeSig(sig)
}

export function decodeSig (sig: Buffer | string): Signature {
  return schema.ECSignature.decode(sigToBuf(sig))
}

export interface SignatureInput {
  pubKey: PublicKey
  sig: string | Buffer
}

function toSignature (sig: SignatureInput): Signature {
  if (Buffer.isBuffer(sig.sig)) {
    return sig as Signature
  }
  return {
    pubKey: sig.pubKey,
    sig: Buffer.from(sig.sig, 'hex')
  }
}

export function encodeSig (sig: SignatureInput): Buffer {
  return schema.ECSignature.encode(toSignature(sig))
}

/**
 * return a value synchronously or asynchronously
 * depending on if callback is passed
 *
 * @deprecated Use of this is an anti-pattern. If you disagree, please explain in a PR.
 */
export function maybeAsync <T> (val: T): T
export function maybeAsync <T> (val: T, cb: (err: null, val: T) => void): undefined
export function maybeAsync <T> (val: T, cb?: (err: null, val: T) => void): T | undefined {
  if (cb != null) {
    queueMicrotask(function () {
      cb(null, val)
    })
  }

  return val
}

export function genECKey (curveType: string = 'secp256k1'): Key {
  let priv: Buffer
  let pub: Buffer
  if (curveType === 'secp256k1') {
    do {
      priv = crypto.randomBytes(32)
    } while (!secp256k1.privateKeyVerify(priv))

    pub = Buffer.from(secp256k1.publicKeyCreate(priv, false))
  } else {
    const pair = curve(curveType).genKeyPair()
    priv = pair.getPrivate().toBuffer()
    pub = Buffer.from(pair.getPublic(false, 'array'))
  }

  return {
    priv,
    pub,
    curve: curveType
  }
}
