require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const User = require("./models/User");
const { verifyToken } = require("./middleware/auth");

const app = express();

app.use(express.json());
app.use(cookieParser());


mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));


app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = new User({
      email,
      password: hashedPassword
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ message: "Invalid credentials" });

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      accessToken,
      refreshToken
    });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken)
    return res.status(401).json({ message: "Refresh token required" });

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
    if (err)
      return res.status(403).json({ message: "Invalid refresh token" });

    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ accessToken: newAccessToken });
  });
});


app.get("/profile", verifyToken, (req, res) => {
  res.json({
    message: "Access granted",
    userId: req.user.userId
  });
});

app.listen(process.env.PORT, () =>
  console.log(`Server running on port ${process.env.PORT}`)
);
