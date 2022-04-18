/* eslint-disable @typescript-eslint/array-type */
/* eslint-disable @typescript-eslint/consistent-type-definitions */
/* eslint-disable @typescript-eslint/naming-convention */
import { Buffer } from 'buffer'
interface Codec <T> {
  buffer: true
  encodingLength: (input: T) => number
  encode: (input: T, buffer?: Buffer, offset?: number) => Buffer
  decode: (input: Buffer, offset?: number, end?: number) => T
}
declare namespace schema {
  namespace def {
    interface ECSignature {
      pubKey: ECPubKey
      sig: Buffer
    }
    interface ECPubKey {
      curve: string
      pub: Buffer
    }
  }
  const ECSignature: Codec<def.ECSignature>
  const ECPubKey: Codec<def.ECPubKey>
}
export = schema
