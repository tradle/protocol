exports.string = `
  message ECSignature {
    required ECPubKey pubKey = 1;
    required bytes sig = 2;
  }

  message ECPubKey {
    required string curve = 1;
    required bytes pub = 2;
  }
`

exports.schema = require('protocol-buffers')(exports.string)
