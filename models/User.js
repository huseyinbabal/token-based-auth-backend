var mongoose     = require('mongoose');
var Schema       = mongoose.Schema;

var UserSchema   = new Schema({
    email: String,
    email: String,
    token: String
});

module.exports = mongoose.model('User', UserSchema);