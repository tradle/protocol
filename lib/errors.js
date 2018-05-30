
const ex = require('error-ex')
const ProtocolError = ex('ProtocolError')

class InvalidInput extends ProtocolError {
  constructor(message) {
    super(message)
  }
}

class InvalidVersion extends InvalidInput {
  constructor(message) {
    super(message)
  }
}

module.exports = {
  InvalidInput,
  InvalidVersion
}
