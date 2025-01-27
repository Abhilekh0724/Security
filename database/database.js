// const mongoose = require("mongoose");

// const connectDb = async () => {
//   try {
//     await mongoose.connect(process.env.MONGODB_URL, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     console.log("Database connected successfully");
//   } catch (error) {
//     console.error("Database connection error:", error.message);
//     process.exit(1); // Exit the process with failure
//   }
// };
const mongoose = require("mongoose");

const connectDb = () =>
  mongoose.connect(process.env.MONGODB_URL).then(() => {
    console.log("Database connected successfully");
  });

module.exports = connectDb;
