import type { Author, Key, PublicKey, Recipient, Signable } from '@tradle/constants/types'
import type { Leaf, LeafHash, Node, ParentHash } from '@tradle/merkle-tree-stream/types'
import test = require('fresh-tape')
import crypto = require('crypto')
import protocol = require('../index')
import types = require('../lib/types')
import utils = require('../lib/utils')
import constants = require('@tradle/constants')
import omit = require('lodash/omit')

const {
  TYPE,
  AUTHOR,
  TIMESTAMP,
  PROTOCOL_VERSION,
  SIG,
  VERSION,
  PREVLINK,
  PERMALINK,
  PREVHEADER,
  WITNESSES
} = constants

test('primitives', function (t) {
  const v1 = protocol.object({
    object: {
      [PROTOCOL_VERSION]: '4.0.0',
      [TYPE]: 'something',
      [AUTHOR]: 'bob',
      [TIMESTAMP]: 12345,
      a: 1,
      b: 2
    }
  })

  const v1MerkleRoot = protocol.merkleRoot(v1)
  t.same(v1MerkleRoot, Buffer.from('6cfc94fcc58422bec23dfb8eb8ccd28b21109b888766f54f344372937c34028f', 'hex'))

  const hashes = [
    '525d236f35b0cbc8bfec9f9d9e5476f26edaad09550d7d745709af613ab2b58a',
    '69835a6705789952f77a107ca7679bd808794c01e9a4959d9af8a4241be6c0f0',
    '54381466f9d03c55cab69ba565dce80f78d67d491190144e932ed900316964d5',
    '976786dba0a124da9950604b1b762d4e7037db19e48a2f179e022756e280e5d4'
  ].map(hash => Buffer.from(hash, 'hex')) as [Buffer, Buffer, Buffer, Buffer]

  const tree = protocol.merkleTreeFromHashes(hashes)

  const { leaf, parent } = protocol.DEFAULT_MERKLE_OPTS
  const dummyNode = { data: null, hash: Buffer.alloc(0), index: 0, size: 0, parent: 0 }
  const hashLeaf = (data: Buffer): Buffer => {
    const input: Leaf<Buffer> = { ...dummyNode, data }
    return leaf(input, [])
  }
  const hashParent = (a: Buffer, b: Buffer): Buffer => {
    const inputA: Node<Buffer> = { ...dummyNode, hash: a }
    const inputB: Node<Buffer> = { ...dummyNode, hash: b }
    return parent(inputA, inputB)
  }
  t.same(tree.root, hashParent(
    hashParent(
      hashLeaf(hashes[0]),
      hashLeaf(hashes[1])
    ),
    hashParent(
      hashLeaf(hashes[2]),
      hashLeaf(hashes[3])
    )
  ))

  t.same(tree.root, Buffer.from('1f8c6bf0d369605aa5f755a67f60c7e3ab567b7679eab2d766011bd8b1aaafbc', 'hex'))

  t.end()
})

test('no undefined', function (t) {
  const bad: Signable[] = [
    { blah: undefined } as any as Signable,
    { [TYPE]: 'ok', blah: undefined } as any as Signable
  ]

  bad.forEach((obj: any) => {
    t.throws(function () {
      types.object.assert(obj)
    })

    t.throws(function () {
      types.object.assert(types.rawObject(obj))
    })
  })

  t.end()
})

test('sign/verify', async t => {
  const [bob] = newPeople(1)
  const object = protocol.object({
    object: {
      [TYPE]: 'blah',
      [AUTHOR]: bob.link,
      a: 1,
      b: 2
    }
  })

  const result = await protocol.promises.sign({
    object,
    author: bob.author
  })
  t.ok(protocol.verify({
    object: result.object
  }))
})

test('seals', async t => {
  const [alice, bob] = newPeople(2)
  const rawV1 = {
    a: 1,
    b: 2,
    c: {
      e: null
    },
    [TYPE]: 'something',
    [AUTHOR]: bob.link
  }

  const v1 = protocol.object({ object: rawV1 })
  t.throws(function () {
    protocol.sealPubKey({
      object: v1,
      basePubKey: alice.chainPubKey
    } as any as types.CalcSealOpts)
  }, /signed/)

  const { object: signed } = await protocol.promises.sign({
    object: v1,
    author: bob.author
  })

  const sealPubKey = protocol.sealPubKey({
    object: signed,
    basePubKey: alice.chainPubKey
  })

  t.ok(protocol.verifySealPubKey({
    object: signed,
    basePubKey: alice.chainPubKey,
    sealPubKey: sealPubKey
  }))

  t.notOk(protocol.verifySealPubKey({
    object: signed,
    basePubKey: bob.chainPubKey,
    sealPubKey: sealPubKey
  }))

  const rawV2 = {
    ...omit(signed, SIG),
    c: 3,
    [VERSION]: 1,
    [PREVLINK]: protocol.linkString(signed),
    [PERMALINK]: protocol.linkString(signed),
    [PREVHEADER]: protocol.headerHash(signed)
  }

  const v2 = protocol.object({
    object: rawV2,
    prev: signed,
    orig: signed
  })

  const { object: signed2 } = await protocol.promises.sign({
    object: v2,
    author: bob.author
  })
  const sealPrevPubKey = protocol.sealPrevPubKey({
    object: signed2,
    basePubKey: alice.chainPubKey
  })

  t.same(sealPrevPubKey, protocol.sealPrevPubKey({
    prevHeaderHash: signed2[PREVHEADER],
    basePubKey: alice.chainPubKey
  }))

  t.ok(protocol.verifySealPrevPubKey({
    object: signed2,
    basePubKey: alice.chainPubKey,
    sealPrevPubKey
  }))

  t.notOk(protocol.verifySealPrevPubKey({
    object: signed2,
    basePubKey: bob.chainPubKey,
    sealPrevPubKey
  }))
})

test('validateVersioning', async t => {
  const bob = newPerson()
  const v1 = protocol.object({
    object: {
      a: 1,
      b: 2,
      [TYPE]: 'something',
      [AUTHOR]: bob.link,
      [TIMESTAMP]: Date.now()
    }
  })

  const result = await protocol.promises.sign({
    object: v1,
    author: bob.author
  })
  const signed = result.object
  t.throws(() => {
    protocol.validateVersioning({
      object: {
        [VERSION]: 0,
        a: 2,
        b: 2
      } as any,
      prev: signed as any
    })
  }, 'At version 0 we dont expect a previous entry')

  t.throws(() => {
    protocol.validateVersioning({
      object: {
        [VERSION]: 1,
        a: 2,
        b: 2
      } as any,
      prev: signed as any
    })
  })

  t.throws(() => {
    protocol.validateVersioning({
      object: {
        [VERSION]: 1,
        [PREVLINK]: crypto.randomBytes(32),
        a: 2,
        b: 2
      } as any,
      prev: signed as any
    })
  })

  t.throws(() => {
    protocol.validateVersioning({
      object: {
        [VERSION]: 1,
        [PREVLINK]: crypto.randomBytes(32),
        [PREVHEADER]: crypto.randomBytes(32),
        a: 2,
        b: 2
      } as any,
      prev: signed as any
    })
  })

  t.throws(() => {
    protocol.validateVersioning({
      object: {
        [VERSION]: 1,
        [PREVLINK]: protocol.linkString(signed),
        [PREVHEADER]: crypto.randomBytes(32),
        a: 2,
        b: 2
      } as any,
      prev: signed as any
    })
  })

  t.throws(() => {
    protocol.validateVersioning({
      object: {
        [VERSION]: 1,
        [PREVLINK]: protocol.linkString(signed),
        [PREVHEADER]: protocol.headerHash(signed),
        a: 2,
        b: 2
      } as any,
      prev: signed as any
    })
  })

  const valid = {
    [VERSION]: 1,
    [PREVLINK]: protocol.linkString(signed),
    [PERMALINK]: protocol.linkString(signed),
    [PREVHEADER]: protocol.headerHash(signed),
    [TIMESTAMP]: Date.now(),
    a: 2,
    b: 2
  }

  protocol.validateVersioning({
    object: valid,
    prev: signed as any,
    orig: signed
  })
  t.pass('Validated')
})

test('versioning', async t => {
  const bob = newPerson()
  const v1 = protocol.object({
    object: {
      a: 1,
      b: 2,
      [TYPE]: 'something',
      [VERSION]: 0,
      [AUTHOR]: bob.link,
      [TIMESTAMP]: Date.now()
    }
  })

  const { object: signedV1 } = await protocol.promises.sign({
    object: v1,
    author: bob.author
  })
  t.doesNotThrow(() => protocol.validateVersioning({ object: signedV1 }))
  t.same(protocol.sigPubKey({ object: signedV1 }), bob.sigPubKey)

  const v2 = protocol.object({
    object: {
      a: 1,
      b: 2,
      c: 3,
      [AUTHOR]: bob.link,
      [TYPE]: 'something',
      [VERSION]: 1,
      [PREVHEADER]: protocol.headerHash(signedV1),
      [PREVLINK]: protocol.linkString(signedV1),
      [PERMALINK]: protocol.linkString(signedV1),
      [TIMESTAMP]: Date.now()
    },
    prev: signedV1,
    orig: signedV1
  })

  const { object: signedV2 } = await protocol.promises.sign({
    object: v2,
    author: bob.author
  })

  t.throws(function () {
    protocol.validateVersioning({
      object: signedV2
    })
  })

  t.throws(function () {
    const invalid = {
      object: signedV2,
      authorPubKey: bob.sigPubKey,
      prev: signedV1
    }
    protocol.validateVersioning(invalid)
  })

  t.throws(function () {
    const bad = omit(signedV2, PREVLINK)
    protocol.validateVersioning({
      object: bad
    })
  })

  t.doesNotThrow(function () {
    protocol.validateVersioning({
      object: signedV2,
      prev: signedV1,
      orig: signedV1
    })
  })
})

test('prove, verify', function (t) {
  const msg = {
    a: 1,
    b: 2,
    c: 3
  }

  const tree = protocol.tree(msg)
  const indices = protocol.indices(msg)

  // prove key 'a', and value under key 'c'
  const proved = [
    tree.nodes[indices.a.key] as types.TradleLeaf,
    tree.nodes[indices.c.value] as types.TradleLeaf
  ]

  const proof = protocol.prove({
    nodes: tree.nodes,
    leaves: proved
  })

  const provedIndices = proved.map(function (node) {
    return node.index
  })

  protocol.leaves(tree.nodes).forEach(function (node) {
    const i = node.index
    const method = provedIndices.includes(i) ? 'ok' : 'notOk'
    t[method](protocol.verifyProof({
      proof: proof,
      node: node as types.TradleLeaf
    }))
  })

  t.end()
})

test('prove with builder, verify', function (t) {
  const msg = {
    a: 1,
    b: 2,
    c: 3
  }

  // prove key 'a', and value under key 'c'
  const tree = protocol.tree(msg)
  const proof = protocol.prover(msg)
    .add({
      property: 'a',
      key: true
    })
    .add({
      property: 'c',
      value: true
    })
    .proof()

  const proved = [
    tree.indices.a.key,
    tree.indices.c.value
  ]

  protocol.leaves(tree.nodes).forEach(function (node) {
    const i = node.index
    const method = proved.includes(i) ? 'ok' : 'notOk'
    t[method](protocol.verifyProof({
      proof: proof,
      node: node as types.TradleLeaf
    }))
  })

  t.end()
})

test('use different hash', async t => {
  const people = newPeople(1)
  const bob = people[0]
  const object = protocol.object({
    object: {
      [TYPE]: 'blah',
      [AUTHOR]: bob.link,
      [VERSION]: 0,
      a: 1,
      b: 2
    }
  })
  const defaults: {
    leaf: LeafHash<Buffer>
    parent: ParentHash<Buffer>
  } = {
    leaf (a) {
      return a.data
    },
    parent (a, b) {
      return Buffer.concat([a.hash, b.hash])
    }
  }

  const { object: signed } = await protocol.promises.sign({
    object,
    author: bob.author,
    ...defaults
  })

  t.ok(protocol.verify({
    object: signed,
    ...defaults
  }))
})

test('sign as witness', async t => {
  const [alice, bob] = newPeople(2)
  const object = protocol.object({
    object: {
      [TYPE]: 'blah',
      [AUTHOR]: alice.link,
      [VERSION]: 0,
      a: 1
    }
  })

  const { object: signed } = await protocol.promises.sign({
    object,
    author: alice.author
  })

  const witnessed = await protocol.promises.witness({
    object: signed,
    author: bob.author,
    permalink: bob.link
  })

  t.ok(protocol.verifyWitnesses({ object: witnessed }))
  t.notOk(protocol.verifyWitnesses({
    object: {
      ...object,
      [WITNESSES]: witnessed[WITNESSES].concat({
        a: 'abc',
        s: 'def'
      })
    }
  }))
})

test('replace embedded media, pre-merklization', function (t) {
  const imageData = Buffer.from('TPnGl7V2hrahqa9ufLMQOJEWyB03eeDDWZHHd5sjcIk=', 'base64')
  const dataUrl = 'data:image/jpeg;base64,' + imageData.toString('base64')
  const v1 = protocol.object({
    object: {
      [PROTOCOL_VERSION]: '4.2.4',
      [TYPE]: 'something',
      [AUTHOR]: 'bob',
      [TIMESTAMP]: 12345,
      dataUrlProp: dataUrl,
      nestedDataUrlProp: {
        a: 1,
        dataUrlProp: dataUrl,
        keeperUriProp: 'tradle-keeper://deadbeef?blah=otherblah'
      },
      keeperUriProp: 'tradle-keeper://deadbeef?blah=otherblah'
    }
  })

  t.same(protocol.preProcessForMerklization(v1), v1)
  v1[PROTOCOL_VERSION] = '5.0.1'

  const input: Leaf<Buffer> = { data: imageData, hash: Buffer.alloc(0), index: 0, parent: 0, size: 0 }
  const expectedDataUrlReplacement = protocol.DEFAULT_MERKLE_OPTS.leaf(
    input,
    []
  ).toString('hex')
  const expectedKeeperUriReplacement = 'deadbeef'
  const preprocessed = protocol.preProcessForMerklization(v1)
  t.same(preprocessed, {
    ...v1,
    dataUrlProp: expectedDataUrlReplacement,
    nestedDataUrlProp: {
      ...v1.nestedDataUrlProp,
      dataUrlProp: expectedDataUrlReplacement,
      keeperUriProp: expectedKeeperUriReplacement
    },
    keeperUriProp: expectedKeeperUriReplacement
  })

  t.same(preprocessed.dataUrlProp, expectedDataUrlReplacement)
  t.end()
})

interface Person {
  chainKey: Key
  sigKey: Key
  link: string
  chainPubKey: PublicKey
  sigPubKey: PublicKey
  author: Author
  recipient: Recipient
}

function toPubKey (key: Key): PublicKey {
  return {
    curve: key.curve,
    pub: key.pub
  }
}

function newPerson (): Person {
  const chainKey = protocol.genECKey()
  const sigKey = protocol.genECKey('p256')
  const chainPubKey = toPubKey(chainKey)
  const sigPubKey = toPubKey(sigKey)
  const link = crypto.randomBytes(32).toString('hex')
  const author: Author = {
    sigPubKey,
    sign: function (merkleRoot, cb) {
      cb(null, utils.sign(merkleRoot, sigKey))
    }
  }
  const recipient: Recipient = {
    pubKey: sigPubKey,
    link
  }
  return {
    chainKey,
    sigKey,
    link,
    sigPubKey,
    chainPubKey,
    author,
    recipient
  }
}

type ArrayN<N, T> = (
  N extends 1
    ? [T]
    : N extends 2
      ? [T, T]
      : N extends 3
        ? [T, T, T]
        : N extends 4
          ? [T, T, T, T]
          : N extends 5
            ? [T, T, T, T, T]
            : N extends 6
              ? [T, T, T, T, T, T]
              : T[]
)

function newPeople <N extends number> (n: N): ArrayN<N, Person> {
  const people: Person[] = []
  for (let i = 0; i < n; i++) {
    people.push(newPerson())
  }

  return people as ArrayN<N, Person>
}
