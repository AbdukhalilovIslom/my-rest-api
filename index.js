import User from "./models/User.js";
import bcrypt from "bcrypt";
import { generateUserToken } from "./services/token.js";
import * as dotenv from "dotenv";
import mongoose from "mongoose";
import express from "express";
import cors from "cors";

// Create an instance of the express application
const app = express();
dotenv.config();

app.use(cors());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS,CONNECT,TRACE"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Content-Type-Options, Accept, X-Requested-With, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
  );
  res.setHeader("Access-Control-Allow-Credentials", true);
  res.setHeader("Access-Control-Allow-Private-Network", true);
  //  Firefox caps this at 24 hours (86400 seconds). Chromium (starting in v76) caps at 2 hours (7200 seconds). The default value is 5 seconds.
  res.setHeader("Access-Control-Max-Age", 7200);

  next();
});

// Middleware to parse incoming request data
app.use(express.json());

// Connect to the MongoDB database
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Check the database connection
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function () {
  console.log("Connected to the database");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const existUser = await User.findOne({ email });
  if (existUser) {
    return res.status(400).send("User already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({
    name: name,
    email: email,
    password: hashedPassword,
    status: "active",
  });

  await user.save();
  res.status(200).json(user);
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.delete("/user/delete/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findByIdAndRemove(id);
    if (!user) {
      return res.status(404).send("User not found");
    }
    res.status(200).json(await User.find());
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Fill inputs.");
  }
  const existUser = await User.findOne({ email });
  if (!existUser) {
    return res.status(400).send("User already exist");
  }
  const isPassEqual = await bcrypt.compare(password, existUser.password);
  if (!isPassEqual) {
    return res.status(400).send("Incorrect password!");
  }
  const token = generateUserToken(existUser._id);
  res.status(200).send({ token });
});

app.put("/users/update/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, status, email, password } = req.body;

    // Find the user by ID and update the fields
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        name,
        email,
        password,
        status,
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).send("User not found");
    }

    res.status(200).send(updatedUser);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.delete("/users/delete", async (req, res) => {
  try {
    const { ids } = req.body;

    // Check if the request contains IDs to delete
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).send("Please provide valid user IDs to delete");
    }

    // Delete users based on the array of IDs
    const deletionResult = await User.deleteMany({ _id: { $in: ids } });

    if (deletionResult.deletedCount === 0) {
      return res.status(404).send("Users not found");
    }

    res.status(200).send(await User.find());
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

// Start the server
const PORT = process.env.PORT || 4100;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
