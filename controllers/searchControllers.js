const Category = require('../models/adminModels');

const searchCategory = async (req, res) => {
  const searchQuery = req.query.q || "";
  const searchCategory = req.query.tags || "";

  try {
    const filter = {};

    if (searchQuery) {
      filter.name = { $regex: searchQuery, $options: "i" }; // Search by category name
    }

    if (searchCategory) {
      filter.info = { $regex: searchCategory, $options: "i" }; // Search by category info
    }

    // Find categories
    const categories = await Category.find(filter);
    res.status(200).json({
      success: true,
      message: "Categories Fetched!",
      categories: categories,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Server Error!",
    });
  }
};

module.exports = {
  searchCategory,
};
