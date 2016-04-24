
const ec = require('elliptic').ec('secp256k1')
const alice = secp256k1.keyFromPrivate('a243732f222cae6f8fc85c302ac6e704799a6b95660fe53b0718a2e84218a718', 'hex')
const bob = secp256k1.keyFromPrivate('06e5db45f217a0bc399a4fd1836ca3bcde392a05b1d67e77d681e490a1039eef', 'hex')

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

// a.destKey.getPublic(true, 'hex') === b.destKey.getPublic(true, 'hex')

const msg = {
  a: 1,
  b: 2,
  c: 3
}

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

const treeIndex = protocol.getIndex(msg)

// prove key 'a'
protocol.verify({ proof: proof, node: treeIndex.a.key }) // true

// prove value 3
protocol.verify({ proof: proof, node: treeIndex.c.value }) // true

// prove key 'b'
protocol.verify({ proof: proof, node: treeIndex.b.key }) // false
