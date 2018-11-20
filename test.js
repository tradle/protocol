'use strict'

const crypto = require('crypto')
const typeforce = require('typeforce')
const test = require('tape')
const secp256k1 = require('secp256k1')
const protocol = require('./')
const {
  TYPE,
  VERSION,
  AUTHOR,
  SIG,
  PREVLINK,
  PERMALINK,
  TIMESTAMP,
  PREVHEADER,
  WITNESSES,
  PROTOCOL_VERSION,
} = require('@tradle/constants')
const types = require('./lib/types')
// const proto = require('./lib/proto')
const utils = require('./lib/utils')
// const keys = require('./fixtures.json').ecKeys.map(function (key) {
//   return new Buffer(key, 'hex')
// })

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
//     rethrow(err)

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
  const v1 = protocol.object({
    object: {
      [PROTOCOL_VERSION]: '4.0.0',
      [TYPE]: 'something',
      [AUTHOR]: 'bob',
      [TIMESTAMP]: 12345,
      a: 1,
      b: 2,
    }
  })

  const v1MerkleRoot = protocol.merkleRoot(v1)
  t.same(v1MerkleRoot, new Buffer('6cfc94fcc58422bec23dfb8eb8ccd28b21109b888766f54f344372937c34028f','hex'))
  t.end()
})

test('no undefined', function (t) {
  const bad = [
    { blah: undefined },
    { [TYPE]: 'ok', blah: undefined }
  ]

  bad.forEach(obj => {
    t.throws(function () {
      typeforce(types.object(obj))
    })

    t.throws(function () {
      typeforce(types.rawObject(obj))
    })
  })

  t.end()
})

test('sign/verify', function (t) {
  const people = newPeople(2)
  const alice = people[0]
  const bob = people[1]

  const object = protocol.object({
    object: {
      [TYPE]: 'blah',
      [AUTHOR]: bob.link,
      a: 1,
      b: 2
    }
  })

  protocol.sign({
    object,
    author: bob.author
  }, function (err, result) {
    rethrow(err)

    t.ok(protocol.verify({ object: result.object }))
    t.end()
  })
})

// test('bob sends, alice receives, carol audits', function (t) {
//   var obj = {
//     [TYPE]: 'blah',
//     a: 1,
//     b: 2
//   }

//   const people = newPeople(3)
//   const alice = people[0]
//   const bob = people[1]
//   const carol = people[2]

//   protocol.sign({
//     object: obj,
//     author: bob.author
//   }, function (err, result) {
//     rethrow(err)

//     // bob sends
//     protocol.message({
//       author: bob.author,
//       body: {
//         recipientPubKey: alice.sigPubKey,
//         object: result.object
//       }
//     }, function (err, result) {
//       rethrow(err)

//       const message = result.object
//       t.doesNotThrow(function () {
//         typeforce({
//           recipientPubKey: types.ecPubKey,
//           object: typeforce.Object,
//           [SIG]: typeforce.String
//         }, message)
//       })

//       t.doesNotThrow(() => protocol.validateMessage({ object: message }))
//       t.end()
//     })
//   })
// })

test('seals', function (t) {
  const people = newPeople(3)
  const alice = people[0]
  const bob = people[1]
  const rawV1 = {
    a: 1,
    b: 2,
    c: {
      // d: undefined,
      e: null
    },
    [TYPE]: 'something',
    [AUTHOR]: bob.link
  }

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
    rethrow(err)

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

    const rawV2 = utils.extend({}, signed, {
      c: 3,
      [VERSION]: 1,
      [PREVLINK]: protocol.linkString(signed),
      [PERMALINK]: protocol.linkString(signed),
      [PREVHEADER]: protocol.headerHash(signed),
    })

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
      rethrow(err)

      const signed = result.object
      const sealPrevPubKey = protocol.sealPrevPubKey({
        object: signed,
        basePubKey: alice.chainPubKey
      })

      t.same(sealPrevPubKey, protocol.sealPrevPubKey({
        prevHeaderHash: signed[PREVHEADER],
        basePubKey: alice.chainPubKey
      }))

      t.ok(protocol.verifySealPrevPubKey({
        object: signed,
        basePubKey: alice.chainPubKey,
        sealPrevPubKey
      }))

      t.notOk(protocol.verifySealPrevPubKey({
        object: signed,
        basePubKey: bob.chainPubKey,
        sealPrevPubKey
      }))

      t.end()
    })
  })
})

test('validateVersioning', function (t) {
  const bob = newPerson()
  const v1 = protocol.object({
    object: {
      a: 1,
      b: 2,
      [TYPE]: 'something',
      [AUTHOR]: bob.link,
    }
  })

  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err, result) {
    rethrow(err)

    const signed = result.object
    t.throws(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 0,
          a: 2,
          b: 2
        },
        prev: signed
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 1,
          a: 2,
          b: 2
        },
        prev: signed
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 1,
          a: 2,
          b: 2,
          [PREVLINK]: crypto.randomBytes(32)
        },
        prev: signed
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 1,
          a: 2,
          b: 2,
          [PREVLINK]: crypto.randomBytes(32),
          [PREVHEADER]: crypto.randomBytes(32),
        },
        prev: signed
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 1,
          a: 2,
          b: 2,
          [PREVLINK]: protocol.linkString(signed),
          [PREVHEADER]: crypto.randomBytes(32),
        },
        prev: signed
      })
    })

    t.throws(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 1,
          a: 2,
          b: 2,
          [PREVLINK]: protocol.linkString(signed),
          [PREVHEADER]: protocol.headerHash(signed)
        },
        prev: signed
      })
    })

    t.doesNotThrow(function () {
      protocol.validateVersioning({
        object: {
          [VERSION]: 1,
          a: 2,
          b: 2,
          [PREVLINK]: protocol.linkString(signed),
          [PERMALINK]: protocol.linkString(signed),
          [PREVHEADER]: protocol.headerHash(signed)
        },
        prev: signed,
        orig: signed
      })
    })

    t.end()
  })
})

test('versioning', function (t) {
  const people = newPeople(3)
  const alice = people[0]
  const bob = people[1]
  const carol = people[2]
  const v1 = protocol.object({
    object: {
      a: 1,
      b: 2,
      [TYPE]: 'something',
      [VERSION]: 0,
      [AUTHOR]: bob.link
    }
  })

  protocol.sign({
    object: v1,
    author: bob.author
  }, function (err, result) {
    rethrow(err)

    const signedV1 = result.object
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
      },
      prev: signedV1,
      orig: signedV1
    })

    protocol.sign({
      object: v2,
      author: bob.author
    }, function (err, result) {
      rethrow(err)

      const signed = result.object
      t.throws(function () {
        protocol.validateVersioning({
          object: signed
        })
      })

      t.throws(function () {
        protocol.validateVersioning({
          object: signed,
          authorPubKey: bob.sigPubKey,
          prev: signedV1
        })
      })

      t.throws(function () {
        const bad = utils.omit(signed, PREVLINK)
        protocol.validateVersioning({
          object: bad
        })
      })

      t.doesNotThrow(function () {
        protocol.validateVersioning({
          object: signed,
          prev: signedV1,
          orig: signedV1
        })
      })

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

test('use different hash', function (t) {
  const people = newPeople(2)
  const alice = people[0]
  const bob = people[1]
  const object = protocol.object({
    object: {
      [TYPE]: 'blah',
      [AUTHOR]: bob.link,
      [VERSION]: 0,
      a: 1,
      b: 2
    }
  })

  const defaultMerkleOpts = protocol.DEFAULT_MERKLE_OPTS
  protocol.DEFAULT_MERKLE_OPTS = {
    leaf: function (a) {
      return a.data
    },
    parent: function (a, b) {
      return Buffer.concat([a.hash, b.hash])
    }
  }

  protocol.sign({
    object,
    author: bob.author,
  }, function (err, result) {
    rethrow(err)

    t.ok(protocol.verify({ object: result.object }))
    protocol.DEFAULT_MERKLE_OPTS = defaultMerkleOpts
    t.end()
  })
})

test('sign as witness', function (t) {
  const people = newPeople(2)
  const [alice, bob] = people
  const object = protocol.object({
    object: {
      [TYPE]: 'blah',
      [AUTHOR]: alice.link,
      [VERSION]: 0,
      a: 1,
    }
  })

  protocol.sign({
    object,
    author: alice.author,
  }, function (err, result) {
    rethrow(err)

    const signed = result.object
    protocol.witness({
      object: signed,
      author: bob.author,
      permalink: bob.link
    }, (err, witnessed) => {
      rethrow(err)

      t.ok(protocol.verifyWitnesses({ object: witnessed }))
      t.notOk(protocol.verifyWitnesses({
        object: utils.extend({}, object, {
          [WITNESSES]: witnessed[WITNESSES].concat({
            a: 'abc',
            s: 'def'
          })
        })
      }))

      t.end()
    })
  })
})

test('replace embedded media, pre-merklization', function (t) {
  const imageData = new Buffer('TPnGl7V2hrahqa9ufLMQOJEWyB03eeDDWZHHd5sjcIk=', 'base64')
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
        keeperUriProp: 'tradle-keeper://deadbeef?blah=otherblah',
      },
      keeperUriProp: 'tradle-keeper://deadbeef?blah=otherblah',
    }
  })

  t.same(protocol.preProcessForMerklization(v1), v1)
  v1[PROTOCOL_VERSION] = '5.0.1'

  const expectedDataUrlReplacement = protocol.DEFAULT_MERKLE_OPTS.leaf({ data: imageData }).toString('hex')
  const expectedKeeperUriReplacement = 'deadbeef'
  const preprocessed = protocol.preProcessForMerklization(v1)
  t.same(preprocessed, {
    ...v1,
    dataUrlProp: expectedDataUrlReplacement,
    nestedDataUrlProp: {
      ...v1.nestedDataUrlProp,
      dataUrlProp: expectedDataUrlReplacement,
      keeperUriProp: expectedKeeperUriReplacement,
    },
    keeperUriProp: expectedKeeperUriReplacement,
  })

  t.same(preprocessed.dataUrlProp, expectedDataUrlReplacement)
  t.end()
})

function rethrow (err) {
  if (err) throw err
}

function newPerson () {
  var person = {
    chainKey: protocol.genECKey(),
    sigKey: protocol.genECKey('p256'),
    link: crypto.randomBytes(32).toString('hex')
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
