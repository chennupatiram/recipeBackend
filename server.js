const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

dotenv.config(); // Load environment variables

const app = express();

// Multer storage config (saving to "uploads" directory)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = "uploads/";
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://recipesharingfront.onrender.com'],
  methods: 'GET,POST,PUT,DELETE',
  credentials: true
}));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve images

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ MongoDB Connection Error:", err));

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

// Recipe Schema
const RecipeSchema = new mongoose.Schema({
  title: { type: String, required: true },
  ingredients: { type: [String], required: true },
  instructions: { type: String, required: true },
  imageUrl: { type: String },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});

const Recipe = mongoose.model("Recipe", RecipeSchema);

// Middleware for Authentication
const verifyToken = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Access Denied. No Token Provided." });
  }

  const token = authHeader.split(" ")[1]; // Extract token after "Bearer"

  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded; // Attach decoded user info to request
      next();
  } catch (err) {
      return res.status(401).json({ message: "Invalid Token" });
  }
};

// 🔹 User Registration
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required!" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("❌ Registration Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 🔹 User Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "12h" });

    res.json({ token, userId: user._id, username: user.username });
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ✅ GET ALL RECIPES (Public)
app.get("/api/recipes", async (req, res) => {
  try {
    const recipes = await Recipe.find().populate("userId", "username").lean();
    recipes.forEach((recipe) => (recipe.userId = recipe.userId._id.toString())); // Convert ObjectId to string
    res.json(recipes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ GET USER'S RECIPES (Protected)
app.get("/api/my-recipes", verifyToken, async (req, res) => {
  try {
    const userRecipes = await Recipe.find({ userId: req.user.userId }).lean();
    res.json(userRecipes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ ADD RECIPE (Protected)
app.post("/api/recipes", verifyToken, upload.single("image"), async (req, res) => {
  try {
    let { title, ingredients, instructions } = req.body;

    if (typeof ingredients === "string") {
      ingredients = ingredients.split(",").map((i) => i.trim());
    }

    if (!title || !ingredients.length || !instructions) {
      return res.status(400).json({ message: "All fields are required!" });
    }

    const newRecipe = new Recipe({
      title,
      ingredients,
      instructions,
      imageUrl: req.file ? `/uploads/${req.file.filename}` : "",
      userId: req.user.userId,
    });

    await newRecipe.save();
    // res.status(201).json(newRecipe);
    res.status(201).json({
      ...newRecipe._doc,
      imageUrl: `http://localhost:5000${newRecipe.imageUrl}`, // Ensure full path is sent
  });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ✅ DELETE RECIPE (Protected)
app.delete("/api/recipes/:id", verifyToken, async (req, res) => {
  try {
    const recipe = await Recipe.findById(req.params.id);

    if (!recipe) {
      return res.status(404).json({ message: "Recipe not found" });
    }

    if (recipe.userId.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Unauthorized to delete this recipe" });
    }

    if (recipe.imageUrl) {
      const imagePath = path.join(__dirname, recipe.imageUrl);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await Recipe.findByIdAndDelete(req.params.id);
    res.json({ message: "Recipe deleted successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
