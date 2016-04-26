
const crypto = require('crypto')
const test = require('tape')
const protocol = require('./')
const ec = require('elliptic').ec
const secp256k1 = ec('secp256k1')
const alice = secp256k1.keyFromPrivate('a243732f222cae6f8fc85c302ac6e704799a6b95660fe53b0718a2e84218a718', 'hex')
const bob = secp256k1.keyFromPrivate('06e5db45f217a0bc399a4fd1836ca3bcde392a05b1d67e77d681e490a1039eef', 'hex')
const SIG = require('@tradle/constants').SIG

test('send, receive', function (t) {
  protocol.send({
    pub: bob.getPublic(),
    message: {
      a: 1,
      b: 2
    },
    sign: function (data, cb) {
      process.nextTick(function () {
        cb(null, new Buffer(alice.sign(data).toDER()))
      })
    }
  }, function (err, sendRes) {
    if (err) throw err

    protocol.receive({
      priv: bob.priv,
      message: {
        a: 1,
        b: 2
      },
      sig: sendRes.sig,
      verify: function (data, sig, cb) {
        process.nextTick(function () {
          cb(null, alice.verify(data, sig))
        })
      }
    }, function (err, receiveRes) {
      if (err) throw err

      t.equal(sendRes.destKey.getPublic(true, 'hex'), receiveRes.destKey.getPublic(true, 'hex'))
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

  const tree = protocol.tree({
    message: msg
  })

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
  const tree = protocol.tree({
    message: msg
  })

  const proof = protocol.prover({
      message: msg
    })
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

function bsSign (data, cb) {
  // BS sig function
  process.nextTick(function () {
    cb(null, [].reverse.call(data))
  })
}

function bsVerify (data, sig, cb) {
  // BS verify function
  process.nextTick(function () {
    cb(null, [].reverse.call(data).equals(sig))
  })
}

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}
