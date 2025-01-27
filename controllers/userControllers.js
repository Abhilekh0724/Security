const userModel = require("../models/userModels");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const createUser = async (req, res) => {
  console.log(req.body);

  const { firstName, lastName, email, password } = req.body;
  if (!firstName || !lastName || !email || !password) {
    return res.json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({
        success: false,
        message: "User Already Exists!",
      });
    }

    const randomSalt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(password, randomSalt);

    const newUser = new userModel({
      firstName,
      lastName,
      email,
      password: hashPassword,
    });

    await newUser.save();

    res.json({
      success: true,
      message: "User created successfully",
    });
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: "Internal server error",
    });
  }
};

const loginUser = async (req, res) => {
  console.log(req.body);

  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.json({
        success: false,
        message: "Incorrect password",
      });
    }

    const token = await jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET);

    res.json({
      success: true,
      message: "User logged in successfully!",
      token,
      userData: user,
    });
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  createUser,
  loginUser,
};
