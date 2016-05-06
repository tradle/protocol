const typeforce = require('typeforce')
const types = require('./types')

  // message Object {
  //   required bytes json = 1;
  // }

const proto = exports.proto = require('protocol-buffers')(`
  message Message {
    repeated Header header = 1;
    required bytes object = 2;
  }

  message Header {
    required SigInput sigInput = 1;
    required bytes sigKey = 2;
    required bytes sig = 3;
    optional bytes txId = 4;
  }

  message SigInput {
    required bytes merkleRoot = 1;
    required Recipient recipient = 2;
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
`)

exports.serialize = function (opts) {
  typeforce({
    toKey: typeforce.Buffer,
    header: types.header,
    object: typeforce.Object
  }, opts)

  const header = opts.header
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
