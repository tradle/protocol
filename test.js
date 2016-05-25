'use strict'

const crypto = require('crypto')
const typeforce = require('typeforce')
const test = require('tape')
const extend = require('xtend')
const secp256k1 = require('secp256k1')
const protocol = require('./')
const constants = require('./lib/constants')
const types = require('./lib/types')
const proto = require('./lib/proto')
const utils = require('./lib/utils')
// const keys = require('./fixtures.json').ecKeys.map(function (key) {
//   return new Buffer(key, 'hex')
// })

const SIG = constants.SIG
const PREV = constants.PREVLINK
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
//         extend(header, { txId: null })
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
    a: 1,
    b: 2
  }

  const v1 = protocol.object({ object: rawV1 })
  t.same(v1, rawV1)

  const v1MerkleRoot = protocol.merkleRoot(v1)
  t.same(v1MerkleRoot, new Buffer('53a9e941e2ba647d7360fdc9a957cbe3780efa3ad2092fbd58936c79b34ca9c8', 'hex'))
  t.end()
})

test('bob sends, alice receives, carol audits', function (t) {
  var obj = {
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

    t.ok(typeof result.object[SIG] === 'string')

    // bob sends
    protocol.message({
      author: bob.author,
      recipientPubKey: alice.sigPubKey,
      object: result.object
    }, function (err, result) {
      if (err) throw err

      const msg = result.object
      t.doesNotThrow(function () {
        typeforce({
          authorPubKey: types.ecPubKey,
          recipientPubKey: types.ecPubKey,
          object: typeforce.Object,
          [SIG]: typeforce.String
        }, msg)
      })

      // alice receives
      t.doesNotThrow(function () {
        protocol.validateMessage({
          authorPubKey: bob.sigPubKey,
          recipientPubKey: alice.sigPubKey,
          message: msg
        })
      })

      t.throws(function () {
        protocol.validateMessage({
          authorPubKey: alice.sigPubKey,
          recipientPubKey: bob.sigPubKey,
          message: msg
        })
      })

      t.end()
    })
  })
})

test('seals', function (t) {
  const rawV1 = {
    a: 1,
    b: 2
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
  }, function (err) {
    if (err) throw err

    let sealPubKey = protocol.sealPubKey({
      object: v1,
      basePubKey: alice.chainPubKey
    })

    t.ok(protocol.verifySealPubKey({
      object: v1,
      basePubKey: alice.chainPubKey,
      sealPubKey: sealPubKey
    }))

    t.notOk(protocol.verifySealPubKey({
      object: v1,
      basePubKey: bob.chainPubKey,
      sealPubKey: sealPubKey
    }))

    const v2 = protocol.object({ object:
      extend(v1, { c: 3 }),
      prev: v1,
      orig: v1
    })

    protocol.sign({
      object: v2,
      author: bob.author
    }, function (err) {
      if (err) throw err

      let sealPrevPubKey = protocol.sealPrevPubKey({
        object: v2,
        basePubKey: alice.chainPubKey
      })

      t.ok(protocol.verifySealPrevPubKey({
        object: v2,
        basePubKey: alice.chainPubKey,
        sealPrevPubKey: sealPrevPubKey
      }))

      t.notOk(protocol.verifySealPrevPubKey({
        object: v2,
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
    b: 2
  }

  const bob = newPerson()
  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err) {
    if (err) throw err

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          a: 2,
          b: 2
        },
        prev: v1
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          a: 2,
          b: 2,
          [PREV]: crypto.randomBytes(32)
        },
        prev: v1
      })
    })

    t.doesNotThrow(function () {
      protocol.validateVersioning({
        object: {
          a: 2,
          b: 2,
          [PREV]: protocol.link(v1)
        },
        prev: v1
      })
    })

    t.end()
  })
})

test('versioning', function (t) {
  const v1 = {
    a: 1,
    b: 2
  }

  const people = newPeople(3)
  const alice = people[0]
  const bob = people[1]
  const carol = people[2]

  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err) {
    if (err) throw err

    protocol.validateObject({
      object: v1,
      authorPubKey: bob.sigPubKey
    })

    const v2 = protocol.object({
      object: {
        a: 1,
        b: 2,
        c: 3
      },
      prev: v1,
      orig: v1
    })

    protocol.sign({
      object: v2,
      author: bob.author
    }, function (err) {
      if (err) throw err

      t.throws(function () {
        protocol.validateObject({
          object: v2,
          authorPubKey: bob.sigPubKey
        })
      }, /prev/)

      t.throws(function () {
        protocol.validateObject({
          object: v2,
          authorPubKey: bob.sigPubKey,
          prev: v1
        })
      }, /orig/)

      t.throws(function () {
        v2 = utils.omit(v2, PREV)
        protocol.validateObject({
          object: v2,
          authorPubKey: bob.sigPubKey
        })
      })

      t.doesNotThrow(function () {
        protocol.validateObject({
          object: v2,
          authorPubKey: bob.sigPubKey,
          prev: v1,
          orig: v1
        })
      }, /orig/)

      const v3 = protocol.object({
        object: v2,
        prev: v1,
        orig: v1
      })

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
