import constants = require('@tradle/constants')

const { VERSION } = constants

export class ProtocolError extends Error {
  name = 'ProtocolError'
}

export class InvalidInput extends ProtocolError {}

export class InvalidProperty extends InvalidInput {
  property: string
  constructor (property: string, message: string) {
    super(message)
    this.property = property
  }
}

export class InvalidVersion extends InvalidProperty {
  constructor (message: string) {
    super(VERSION, message)
  }
}
