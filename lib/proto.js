const typeforce = require('typeforce')
const constants = require('./constants')
const SIG = constants.SIG
const SEQ = constants.SEQ
const PREV_TO_SENDER = constants.PREV_TO_SENDER
const types = require('./types')
const proto = exports.schema = require('protocol-buffers')(`
  message ECSignature {
    required ECPubKey pubKey = 1;
    required bytes sig = 2;
  }

  message ECPubKey {
    required string curve = 1;
    required bytes pub = 2;
  }

  message PubKey {
    required PubKeyType type = 1;
    optional ECPubKey ec = 2;
    // optional DSAPubKey dsa = 3;
    // optional RSAPubKey rsa = 4;
  }

  enum PubKeyType {
    EC = 1;
    RSA = 2;
    DSA = 3;
  }

  message Message {
    // don't need authorPubKey, SIG, already has it
    // required ECPubKey authorPubKey = 1;
    required ECPubKey recipientPubKey = 1;
    required bytes object = 2;
    required ECSignature ${SIG} = 3;
    optional bytes ${PREV_TO_SENDER} = 4;
    optional uint32 ${SEQ} = 5;
  }
`)

  // message Message {
  //   required bytes object = 1;
  //   required Signature sig = 2;
  // }

  // enum IdentifierType {
  //   ROOT = 0;
  //   CUR = 1;
  //   PUBKEY = 2;
  // }

  // message Recipient {
  //   required IdentifierType identifierType = 1;
  //   required bytes identifier = 2;
  // }

  // message TxData {
  //   required bytes merkleRoot = 1;
  //   required Recipient recipient = 2;
  // }

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

// exports.serialize = function (opts) {
//   typeforce({
//     toKey: typeforce.Buffer,
//     object: typeforce.Object
//   }, opts)

//   return proto.Message.encode({
//     header: [
//       {
//         sig: header.sig,
//         sigKey: header.sigKey,
//         sigInput: {
//           merkleRoot: header.sigInput.merkleRoot,
//           recipient: {
//             identifierType: proto.IdentifierType.PUBKEY,
//             identifier: opts.toKey
//           }
//         }
//       }
//     ],
//     object: new Buffer(JSON.stringify(opts.object))
//   })
// }

// exports.unserialize = function (msg) {
//   msg = exports.proto.Message.decode(msg)
//   const sigInput = msg.header[0].sigInput
//   // only pubKeys for now
//   sigInput.recipient = sigInput.recipient.identifier
//   msg.object = JSON.parse(msg.object)
//   msg.headers = msg.header
//   delete msg.header
//   return msg
// }
