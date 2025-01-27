const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'user',
    required: true,
    unique: true,
  },
  profilePic: {
    type: String,
    default: '',
  },
});

const Profile = mongoose.model('Profile', profileSchema);

module.exports = Profile;
