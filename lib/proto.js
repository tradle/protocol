let string
module.exports = {
  get string () {
    if (string === undefined) {
      string = require('fs')
        .readFileSync(
          require('path').resolve(__dirname, 'schema.proto'),
          'utf-8'
        )
    }
    return string
  },
  schema: require('./schema.js')
}
