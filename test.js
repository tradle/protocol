'use strict'

const crypto = require('crypto')
const typeforce = require('typeforce')
const test = require('tape')
const clone = require('xtend')
const secp256k1 = require('secp256k1')
const protocol = require('./')
const constants = require('./lib/constants')
const types = require('./lib/types')
const proto = require('./lib/proto')
const utils = require('./lib/utils')
// const keys = require('./fixtures.json').ecKeys.map(function (key) {
//   return new Buffer(key, 'hex')
// })

const TYPE = constants.TYPE
const SIG = constants.SIG
const PREV = constants.PREVLINK
const ORIG = constants.PERMALINK
const PREV_TO_SENDER = constants.PREV_TO_SENDER || '_u'

// test('encode, decode', function (t) {
//   var obj = {
//     a: 1,
//     b: 2
//   }

//   // bob sends
//   const toKey = secp256k1.publicKeyCreate(alice.chainKey)
//   protocol.send({
//     toKey: toKey,
//     sigKey: bob.sigKey,
//     object: obj
//   }, function (err, sendRes) {
//     if (err) throw err

//     const header = sendRes.header
//     const serialized = proto.serialize({
//       toKey: toKey,
//       header: sendRes.header,
//       object: sendRes.object
//     })

//     const unserialized = proto.unserialize(serialized)
//     t.same(unserialized, {
//       headers: [
//         clone(header, { txId: null })
//       ],
//       object: sendRes.object
//     })

//     // t.same(unserialized, {
//     //   header: [
//     //     {
//     //       sig: header.sig,
//     //       sigInput: {
//     //         merkleRoot: header.sigInput.merkleRoot,
//     //         recipient: {
//     //           identifier: toKey,
//     //           identifierType: proto.IdentifierType.PUBKEY
//     //         }
//     //       }
//     //     }
//     //   ],
//     //   object: sendRes.object
//     // })

//     t.end()
//   })

// })

test('primitives', function (t) {
  const rawV1 = {
    [TYPE]: 'something',
    a: 1,
    b: 2
  }

  const v1 = protocol.object({ object: rawV1 })
  t.same(v1, rawV1)

  const v1MerkleRoot = protocol.merkleRoot(v1)
  t.same(v1MerkleRoot, new Buffer('1743d6658cd54a59c2fcece177f329217c14452320be8398bdc5252b9261a269','hex'))
  t.end()
})

test('sign/verify', function (t) {
  var object = {
    [TYPE]: 'blah',
    a: 1,
    b: 2
  }

  const people = newPeople(2)
  const alice = people[0]
  const bob = people[1]

  protocol.sign({
    object: object,
    author: bob.author
  }, function (err, result) {
    if (err) throw err

    t.ok(protocol.verify({ object: result.object }))
    t.end()
  })
})

test('bob sends, alice receives, carol audits', function (t) {
  var obj = {
    [TYPE]: 'blah',
    a: 1,
    b: 2
  }

  const people = newPeople(3)
  const alice = people[0]
  const bob = people[1]
  const carol = people[2]

  protocol.sign({
    object: obj,
    author: bob.author
  }, function (err, result) {
    if (err) throw err

    // bob sends
    protocol.message({
      author: bob.author,
      recipientPubKey: alice.sigPubKey,
      object: result.object
    }, function (err, result) {
      if (err) throw err

      const message = result.object
      t.doesNotThrow(function () {
        typeforce({
          recipientPubKey: types.ecPubKey,
          object: typeforce.Object,
          [SIG]: typeforce.String
        }, message)
      })

      t.doesNotThrow(() => protocol.validateMessage({ object: message }))
      t.end()
    })
  })
})

test('seals', function (t) {
  const rawV1 = {
    a: 1,
    b: 2,
    [TYPE]: 'something'
  }

  const people = newPeople(3)
  const alice = people[0]
  const bob = people[1]

  const v1 = protocol.object({ object: rawV1 })
  t.throws(function () {
    let sealPubKey = protocol.sealPubKey({
      object: v1,
      basePubKey: alice.chainPubKey
    })
  }, /signed/)

  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err, result) {
    if (err) throw err

    const signed = result.object
    let sealPubKey = protocol.sealPubKey({
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

    const rawV2 = clone(signed, { c: 3 })
    delete rawV2[SIG]
    const v2 = protocol.object({
      object: rawV2,
      prev: signed,
      orig: signed
    })

    protocol.sign({
      object: v2,
      author: bob.author
    }, function (err, result) {
      if (err) throw err

      const signed = result.object
      let sealPrevPubKey = protocol.sealPrevPubKey({
        object: signed,
        basePubKey: alice.chainPubKey
      })

      t.ok(protocol.verifySealPrevPubKey({
        object: signed,
        basePubKey: alice.chainPubKey,
        sealPrevPubKey: sealPrevPubKey
      }))

      t.notOk(protocol.verifySealPrevPubKey({
        object: signed,
        basePubKey: bob.chainPubKey,
        sealPrevPubKey: sealPrevPubKey
      }))

      t.end()
    })
  })
})

test('validateVersioning', function (t) {
  var v1 = {
    a: 1,
    b: 2,
    [TYPE]: 'something'
  }

  const bob = newPerson()
  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err, result) {
    if (err) throw err

    const signed = result.object
    t.throws(function () {
      protocol.validateVersioning({
        object: {
          a: 2,
          b: 2
        },
        prev: signed
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          a: 2,
          b: 2,
          [PREV]: crypto.randomBytes(32)
        },
        prev: signed
      })
    })

    t.doesNotThrow(function () {
      protocol.validateVersioning({
        object: {
          a: 2,
          b: 2,
          [PREV]: protocol.linkString(signed)
        },
        prev: signed
      })
    })

    t.end()
  })
})

test('versioning', function (t) {
  const v1 = {
    a: 1,
    b: 2,
    [TYPE]: 'something'
  }

  const people = newPeople(3)
  const alice = people[0]
  const bob = people[1]
  const carol = people[2]

  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err, result) {
    if (err) throw err

    const signedV1 = result.object
    t.doesNotThrow(() => protocol.validateVersioning({ object: signedV1 }))
    t.same(protocol.sigPubKey({ object: signedV1 }), bob.sigPubKey)

    const v2 = protocol.object({
      object: {
        a: 1,
        b: 2,
        c: 3,
        [TYPE]: 'something'
      },
      prev: signedV1,
      orig: signedV1
    })

    protocol.sign({
      object: v2,
      author: bob.author
    }, function (err, result) {
      if (err) throw err

      const signed = result.object
      t.throws(function () {
        protocol.validateVersioning({
          object: signed,
          authorPubKey: bob.sigPubKey
        })
      }, /prev/)

      t.throws(function () {
        protocol.validateVersioning({
          object: signed,
          authorPubKey: bob.sigPubKey,
          prev: signedV1
        })
      }, /orig/)

      t.throws(function () {
        signed = utils.omit(signed, PREV)
        protocol.validateVersioning({
          object: signed,
          authorPubKey: bob.sigPubKey
        })
      })

      t.doesNotThrow(function () {
        protocol.validateVersioning({
          object: signed,
          authorPubKey: bob.sigPubKey,
          prev: signedV1,
          orig: signedV1
        })
      }, /orig/)

      // const v3 = protocol.object({
      //   object: v2,
      //   prev: v1,
      //   orig: v1
      // })

      t.end()
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
    tree.nodes[indices.a.key],
    tree.nodes[indices.c.value]
  ]

  const proof = protocol.prove({
    nodes: tree.nodes,
    leaves: proved
  })

  const provedIndices = proved.map(function (node) {
    return node.index
  })

  tree.nodes.forEach(function (node) {
    const i = node.index
    if (i % 2) return

    const method = provedIndices.indexOf(i) === -1 ? 'notOk' : 'ok'
    t[method](protocol.verifyProof({
      proof: proof,
      node: node
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

  tree.nodes.forEach(function (node) {
    const i = node.index
    if (i % 2) return

    const method = proved.indexOf(i) === -1 ? 'notOk' : 'ok'
    t[method](protocol.verifyProof({
      proof: proof,
      node: node
    }))
  })

  t.end()
})

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}

function privToPub (key) {
  return secp256k1.publicKeyCreate(key)
}

function newPerson () {
  var person = {
    chainKey: protocol.genECKey(),
    sigKey: protocol.genECKey('p256'),
    link: crypto.randomBytes(32)
  }

  person.sigPubKey = utils.omit(person.sigKey, 'priv')
  person.chainPubKey = utils.omit(person.chainKey, 'priv')

  // person.chainKey.pub = secp256k1.publicKeyCreate(person.chainKey.priv)
  // person.sigPubKey = secp256k1.publicKeyCreate(person.sigKey.priv)
  person.author = {
    sigPubKey: utils.omit(person.sigKey, 'priv'),
    sign: function (merkleRoot, cb) {
      cb(null, utils.sign(merkleRoot, person.sigKey))
    }
  }

  person.recipient = {
    pubKey: person.sigPubKey,
    link: person.link
  }

  return person
}

function newPeople (n) {
  const people = []
  for (var i = 0; i < n; i++) {
    people.push(newPerson())
  }

  return people
}

process.on('uncaughtException', function (err) {
  if (err.tfError) console.log(err.tfError.stack)

  throw err
})
