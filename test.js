
const crypto = require('crypto')
const typeforce = require('typeforce')
const test = require('tape')
const extend = require('xtend')
const secp256k1 = require('secp256k1')
const constants = require('@tradle/constants')
const protocol = require('./')
const types = require('./lib/types')
const proto = require('./lib/proto')
const utils = require('./lib/utils')
const SIG = constants.SIG
const PREV = constants.PREV_HASH
const PREV_TO_SENDER = constants.PREV_TO_SENDER || '_u'

const alice = {
  chainKey: new Buffer('a243732f222cae6f8fc85c302ac6e704799a6b95660fe53b0718a2e84218a718', 'hex'),
  sigKey: new Buffer('1987cf92acb0fa32232631826c3e7386a853bc1b0f8233903f17990c70f09096', 'hex')
}

const bob = {
  chainKey: new Buffer('06e5db45f217a0bc399a4fd1836ca3bcde392a05b1d67e77d681e490a1039eef', 'hex'),
  sigKey: new Buffer('27572001fe781aa04794fd2bab787edcda182dddf1e4331d2aef6fb88cb73812', 'hex')
}

const carol = {
  chainKey: new Buffer('37fe7e4ba51b148261c4a13378e7825c8e7912b38318f8e55e42fbfe31bb8a1a', 'hex'),
  sigKey: new Buffer('a9d929bae0eee133965398322fb6db8e9285a1cd1c01b1cbc69d2390b433bc41', 'hex')
}

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

test('bob sends, alice receives, carol audits', function (t) {
  var obj = {
    a: 1,
    b: 2
  }

  // bob sends
  protocol.send({
    sender: {
      sigPubKey: privToPub(bob.sigKey),
      sign: function (merkleRoot, cb) {
        cb(null, utils.sign(merkleRoot, bob.sigKey))
      }
    },
    recipient: {
      pubKey: privToPub(alice.chainKey),
      ref: new Buffer('alice')
    },
    object: obj
  }, function (err, sendRes) {
    if (err) throw err

    t.doesNotThrow(function () {
      typeforce({
        objectInfo: typeforce.Object,
        shareInfo: typeforce.Object,
        outputKey: typeforce.Buffer
      }, sendRes)
    })

    // alice receives
    protocol.receive({
      object: sendRes.objectInfo.object,
      share: sendRes.shareInfo.object
    }, function (err, receiveRes) {
      if (err) throw err


      t.same(sendRes.outputKey, receiveRes.outputKey, 'alice and bob derive same per-message key')
      // t.notOk(sendRes.outputKey.priv, 'bob only has per-message public key')
      // t.ok(receiveRes.outputKey.priv, 'alice has per-message private key')

      // carol audits, knowing
      protocol.receive({
        object: obj,
        share: sendRes.shareInfo.object
      }, function (err, processed) {
        if (err) throw err

        t.same(processed.outputKey, receiveRes.outputKey, 'carol derives same per-message key')
        // t.notOk(processed.outputKey.priv, 'carol does not have per-message private key')
        t.end()
      })
    })
  })
})

test('sequence', function (t) {
  var v1 = {
    a: 1,
    b: 2
  }

  var v1merkleRoot = protocol.merkleRoot(v1)
  t.doesNotThrow(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
        [PREV]: v1merkleRoot
      },
      {
        prevVersion: v1
      }
    )
  })

  t.doesNotThrow(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
        [PREV_TO_SENDER]: v1merkleRoot
      },
      {
        prevObjectFromSender: v1
      }
    )
  })

  t.doesNotThrow(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
        [PREV]: v1merkleRoot,
        [PREV_TO_SENDER]: v1merkleRoot
      },
      {
        prevVersion: v1,
        prevObjectFromSender: v1
      }
    )
  })

  t.throws(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
      },
      {
        prevVersion: v1,
      }
    )
  })

  t.throws(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
      },
      {
        prevVersion: v1,
        prevObjectFromSender: v1
      }
    )
  })

  t.throws(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
        [PREV]: v1merkleRoot,
      },
      {}
    )
  })

  t.throws(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
        [PREV_TO_SENDER]: v1merkleRoot
      },
      {}
    )
  })

  t.throws(function () {
    protocol.validateSequence(
      {
        a: 2,
        b: 2,
        [PREV]: v1merkleRoot,
        [PREV_TO_SENDER]: v1merkleRoot
      },
      {
        prevVersion: crypto.randomBytes(32),
        prevObjectFromSender: v1
      }
    )
  })

  t.end()
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
