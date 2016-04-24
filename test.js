
const test = require('tape')
const protocol = require('./')
const ec = require('elliptic').ec
const secp256k1 = ec('secp256k1')
const alice = secp256k1.keyFromPrivate('a243732f222cae6f8fc85c302ac6e704799a6b95660fe53b0718a2e84218a718', 'hex')
const bob = secp256k1.keyFromPrivate('06e5db45f217a0bc399a4fd1836ca3bcde392a05b1d67e77d681e490a1039eef', 'hex')

test('send, receive', function (t) {
  const a = protocol.send({
    pub: bob.getPublic(),
    message: {
      a: 1,
      b: 2
    }
  })

  const b = protocol.receive({
    priv: bob.priv,
    message: {
      a: 1,
      b: 2
    }
  })

  t.equal(a.destKey.getPublic(true, 'hex'), b.destKey.getPublic(true, 'hex'))
  t.end()
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

  const provedIndices = [
    0, 10
  ]

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
