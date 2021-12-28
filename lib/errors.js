
const ex = require('error-ex')
const ProtocolError = ex('ProtocolError')
const { VERSION } = require('./constants')

class InvalidInput extends ProtocolError {}

class InvalidProperty extends InvalidInput {
  constructor (property, message) {
    super(message)
    this.property = property
  }
}

class InvalidVersion extends InvalidProperty {
  constructor (message) {
    super(VERSION, message)
  }
}

module.exports = {
  InvalidInput,
  InvalidProperty,
  InvalidVersion
}
