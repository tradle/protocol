import constants = require('@tradle/constants')

const {
  SIG,
  TYPE,
  VERSION,
  AUTHOR,
  WITNESSES,
  ORG_SIG
} = constants

// Note currently only one property is defined here,
// If more properties are to be added we need to also update getLinkHeader
export const LINK_HEADER_PROPS = [SIG]
export const HEADER_PROPS = [...LINK_HEADER_PROPS, WITNESSES, ORG_SIG]
export const REQUIRED_IDENTITY_PROPS = [...HEADER_PROPS, TYPE, VERSION]
export const REQUIRED_NON_IDENTITY_PROPS = [...REQUIRED_IDENTITY_PROPS, AUTHOR]
