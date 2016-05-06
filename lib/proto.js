const typeforce = require('typeforce')
const types = require('./types')
const proto = exports.schema = require('protocol-buffers')(`
  message Signature {
    required ECPubKey sigPubKey = 1;
    required bytes sig = 2;
  }

  enum IdentifierType {
    ROOT = 0;
    CUR = 1;
    PUBKEY = 2;
  }

  message Recipient {
    required IdentifierType identifierType = 1;
    required bytes identifier = 2;
  }

  message TxData {
    required bytes merkleRoot = 1;
    required Recipient recipient = 2;
  }

  message ECPubKey {
    required string curve = 1;
    required bytes value = 2;
  }
`)


  // message Object {
  //   required bytes json = 1;
  // }

  // message Message {
  //   repeated Header header = 1;
  //   required bytes object = 2;
  // }

  // message Object {
  //   required bytes body = 1;
  //   required Signature sig = 2;
  // }

  // message Object {
  //   required Signature sig = 1;
  //   required bytes body = 2;
  // }

  // message Share {
  //   required Header header = 1;
  //   required Signature sig = 2;
  //   required bytes body = 3;
  // }

exports.serialize = function (opts) {
  typeforce({
    toKey: typeforce.Buffer,
    object: typeforce.Object
  }, opts)

  return proto.Message.encode({
    header: [
      {
        sig: header.sig,
        sigKey: header.sigKey,
        sigInput: {
          merkleRoot: header.sigInput.merkleRoot,
          recipient: {
            identifierType: proto.IdentifierType.PUBKEY,
            identifier: opts.toKey
          }
        }
      }
    ],
    object: new Buffer(JSON.stringify(opts.object))
  })
}

exports.unserialize = function (msg) {
  msg = exports.proto.Message.decode(msg)
  const sigInput = msg.header[0].sigInput
  // only pubKeys for now
  sigInput.recipient = sigInput.recipient.identifier
  msg.object = JSON.parse(msg.object)
  msg.headers = msg.header
  delete msg.header
  return msg
}
