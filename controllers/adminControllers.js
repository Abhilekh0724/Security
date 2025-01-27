const Category = require('../models/adminModels');
const path = require('path');

// Create a new category
const createCategory = async (req, res) => {
  const { price, name, info } = req.body;

  if (!req.files || !req.files.photo) {
    return res.status(400).json({
      success: false,
      message: "Photo not found!",
    });
  }

  const { photo } = req.files;
  const photoName = `${Date.now()}-${photo.name}`;
  const photoUploadPath = path.join(__dirname, '../public/uploads', photoName);

  try {
    await photo.mv(photoUploadPath);

    const newCategory = new Category({
      price,
      name,
      info,
      photo: `/uploads/${photoName}`,
    });

    const category = await newCategory.save();
    res.status(201).json({
      success: true,
      message: "Category Created!",
      data: category,
    });
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: "Internal server error",
      error: error,
    });
  }
};

// Fetch all categories
const getAllCategories = async (req, res) => {
  try {
    const categories = await Category.find({});
    res.status(200).json({
      success: true,
      message: "Categories fetched successfully!",
      categories: categories,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Update a category
const updateCategory = async (req, res) => {
  const { id } = req.params;
  const { price, name, info } = req.body;
  let photoPath;

  if (req.files && req.files.photo) {
    const { photo } = req.files;
    const photoName = `${Date.now()}-${photo.name}`;
    const photoUploadPath = path.join(__dirname, '../public/uploads', photoName);
    try {
      await photo.mv(photoUploadPath);
      photoPath = `/uploads/${photoName}`;
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: "Error uploading photo",
      });
    }
  }

  try {
    const updatedCategory = await Category.findByIdAndUpdate(
      id,
      {
        price,
        name,
        info,
        ...(photoPath && { photo: photoPath }), // Only include photo if it was updated
      },
      { new: true }
    );

    if (!updatedCategory) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Category updated successfully!",
      data: updatedCategory,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Delete a category
const deleteCategory = async (req, res) => {
  const { id } = req.params;

  try {
    const deletedCategory = await Category.findByIdAndDelete(id);

    if (!deletedCategory) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Category deleted successfully!",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  createCategory,
  getAllCategories,
  updateCategory,
  deleteCategory,
};
