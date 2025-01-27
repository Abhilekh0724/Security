const path = require('path');
const fs = require('fs');
const Profile = require('../models/profileModels');

exports.uploadProfilePic = async (req, res) => {
  try {
    const userId = req.user.id; // Get userId from req.user set by authGuard

    if (!req.files || !req.files.profilePic) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const profilePic = req.files.profilePic;
    const uploadPath = path.join(__dirname, '..', 'public', 'uploads', profilePic.name);

    // Save the file
    profilePic.mv(uploadPath, async (err) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'File upload failed', error: err });
      }

      // Update the user's profile picture path in the database
      const updatedProfile = await Profile.findOneAndUpdate(
        { userId: userId },
        { profilePic: `/uploads/${profilePic.name}` },
        { new: true, upsert: true }
      );

      return res.status(200).json({ success: true, profilePic: updatedProfile.profilePic });
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error', error });
  }
};

exports.getUserInfo = async (req, res) => {
  try {
    const userId = req.user.id; // Get userId from req.user set by authGuard

    // Find the user's profile information
    const userProfile = await Profile.findOne({ userId: userId });

    if (!userProfile) {
      return res.status(404).json({ success: false, message: 'User profile not found' });
    }

    return res.status(200).json({ success: true, profile: userProfile });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error', error });
  }
};
