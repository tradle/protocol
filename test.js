
const crypto = require('crypto')
const test = require('tape')
const protocol = require('./')
const ec = require('elliptic').ec
const secp256k1 = ec('secp256k1')
const constants = require('@tradle/constants')
const SIG = constants.SIG
const PREV = constants.PREV_HASH
const PREV_TO_SENDER = constants.PREV_TO_SENDER || '_u'

const alice = {
  // chain: secp256k1.keyFromPrivate('a243732f222cae6f8fc85c302ac6e704799a6b95660fe53b0718a2e84218a718', 'hex'),
  sign: secp256k1.keyFromPrivate('1987cf92acb0fa32232631826c3e7386a853bc1b0f8233903f17990c70f09096', 'hex')
}

const bob = {
  // chain: secp256k1.keyFromPrivate('06e5db45f217a0bc399a4fd1836ca3bcde392a05b1d67e77d681e490a1039eef', 'hex'),
  sign: secp256k1.keyFromPrivate('27572001fe781aa04794fd2bab787edcda182dddf1e4331d2aef6fb88cb73812', 'hex')
}

test('bob sends, alice receives', function (t) {
  t.plan(3)

  var obj = {
    a: 1,
    b: 2
  }

  // bob sends, alice receives
  protocol.send({
    pub: alice.sign.getPublic(),
    object: obj,
    // signingPubKey: alice.getPublic(false, 'hex'),
    sign: function (data, cb) {
      process.nextTick(function () {
        cb(null, new Buffer(bob.sign.sign(data).toDER()))
      })
    }
  }, function (err, sendRes) {
    if (err) throw err

    protocol.receive({
      priv: alice.sign.priv,
      object: obj,
      header: sendRes.header,
      verify: function (data, sig, cb) {
        process.nextTick(function () {
          cb(null, bob.sign.verify(data, sig))
        })
      }
    }, function (err, receiveRes) {
      if (err) throw err

      t.equal(sendRes.destKey.getPublic(true, 'hex'), receiveRes.destKey.getPublic(true, 'hex'), 'alice and bob derive same per-message key')
      t.notOk(sendRes.destKey.priv, 'bob only has per-message public key')
      t.ok(receiveRes.destKey.priv, 'alice has per-message private key')
      t.end()
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
    t[method](protocol.verify({
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
    t[method](protocol.verify({
      proof: proof,
      node: node
    }))
  })

  t.end()
})

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}
