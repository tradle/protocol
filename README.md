# protocol

Tradle protocol v2

# Purpose

Alice sends Bob a message on some channel or other. Later, Bob wants to prove who send what and when. Digital signatures get you 90% of the way there, but you still need an identity server (in our case the blockchain), and message timestamping (you got it, also the blockchain).

The sender and recipient separately derive per-message public keys based on message content and recipient's public key. The proving party, who can be either the sender or the recipient, sends a blockchain transaction to the address corresponding to the generated key. The recipient monitors the same address to get a confidential but auditable proof.

# Methods

Better docs coming soon, for now see documentation embedded in code.

# send({ pub: ECPubKey, message: Object })

# receive({ pub: ECPrivKey, message: Object })

# tree({ leaf: ?Function, parent: ?Function, message: Object })

# prove({ tree: Array, leaves: Array })

# verify({ proof: Array, node: Node })

# Usage 

```js
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
```

# Objects

Objects are plain JSON objects that:
* must bear the signature of their creator (the merkle root of the object is signed)
* if the object is not the first version:
  * must link to the previous version of the object
  * optionally link to the original version of the object (if it exists)

## Merkle root

To build a merkle tree for an object, sort the properties alphabetically, then set the leaves to be key1, value1, key2, value2, etc.

## Object headers

Properties in an object header are omitted from the merkle tree. Header properties include:
  * signature

# Messages

Messages are objects as described above, with the following properties:
* object: another object
* sender: sender pub key
* recipient: recipient pub key
* prev: link to previous message to this recipient

# Links

A link to an object is the sha256 hash of its stringified header, currently:

```json
var header = {
  // merkle root of tree described above
  _s: sign(merkle_root(object))
}
```

# Seals

Seals are public keys that are created as combination of a blockchain transaction creator's known public key and an object:

  p1 = link // private key derived from object link
  P1 = ec_point(p1)
  P2 = transaction creator pub key

  Seal pub key = P1 + P2

When a version of an object is created, two seals are created, one for the current version, and one linking to the previous. The seal pub key for the previous is calculated slightly differently so that it doesn't end up being identical to the previous version's:

  p1 = sha256(prev_version_link)
  ... // same as above
