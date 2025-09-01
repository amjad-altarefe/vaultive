const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: String, 
    role: {type: String, default: 'user'},
    resetPasswordToken: String,
    resetPasswordExpires: Date

});
module.exports = mongoose.model('User', userSchema);

