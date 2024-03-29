const {
  SIG,
  TYPE,
  VERSION,
  AUTHOR,
  WITNESSES,
  ORG_SIG
} = require('@tradle/constants')

const LINK_HEADER_PROPS = [SIG]
const HEADER_PROPS = LINK_HEADER_PROPS.concat([WITNESSES, ORG_SIG])
const REQUIRED_IDENTITY_PROPS = HEADER_PROPS.concat([
  TYPE,
  VERSION
])

const REQUIRED_NON_IDENTITY_PROPS = REQUIRED_IDENTITY_PROPS.concat(AUTHOR)

module.exports = {
  LINK_HEADER_PROPS,
  HEADER_PROPS,
  REQUIRED_IDENTITY_PROPS,
  REQUIRED_NON_IDENTITY_PROPS
}
