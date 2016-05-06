
const typeforce = require('typeforce')

exports.merkleNode = typeforce.compile({
  hash: typeforce.Buffer,
  index: typeforce.Number
})

exports.merkleLeaf = typeforce.compile({
  data: typeforce.Buffer,
  hash: typeforce.Buffer,
  index: typeforce.Number
})

exports.merkleTree = typeforce.compile({
  nodes: typeforce.arrayOf(exports.merkleNode),
  roots: typeforce.arrayOf(exports.merkleNode)
})

// exports.key = typeforce.oneOf(typeforce.String, typeforce.Object)

exports.keyObj = function (val) {
  return Buffer.isBuffer(val.pub) || Buffer.isBuffer(val.priv)
}

exports.merkleRootOrObj = typeforce.oneOf(typeforce.Object, typeforce.Buffer)

// const OBJECT_TYPE = typeforce.compile({
//   header: typeforce.Object,
//   body: typeforce.Object
// })

exports.sigInput = typeforce.compile({
  merkleRoot: typeforce.Buffer,
  recipient: typeforce.Buffer
})

// exports.header = typeforce.compile({
//   sig: typeforce.Buffer,
//   sigKey: typeforce.Buffer,
//   sigInput: exports.sigInput,
//   txId: typeforce.maybe(typeforce.String)
// })
