const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
require("dotenv").config();
/* ================= SOCKET.IO ================= */

const io = new Server(server, {
  cors: { origin: "*" }
});

/* ================= MIDDLEWARE ================= */

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// serve frontend
app.use(express.static("frontend"));

// serve uploaded images
app.use("/uploads", express.static("uploads"));

app.use(session({
  secret: process.env.SESSION_SECRET || "secretkey",
  resave: false,
  saveUninitialized: false
}));

/* ================= DATABASE ================= */

mongoose.connect(process.env.MONGO_URI)
.then(async () => {
  console.log("MongoDB Connected");

  // auto-create admin if not exists
  const adminExists = await User.findOne({ role: "admin" });

  if (!adminExists) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASS, 10);

    await User.create({
      name: "Administrator",
      phone: "9876543210", // change if needed
      password: hash,
      role: "admin"
    });

    console.log("Default admin created");
  }
})
.catch(err => console.log(err));

/* ================= FILE UPLOAD ================= */

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname))
});

const upload = multer({ storage });

/* ================= MODELS ================= */

const complaintSchema = new mongoose.Schema({
  citizen_name: String,
  issue: String,
  ward: String,
  status: String,
  assigned_to: String,
  priority: String,
  photo: String,
  created_at: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
  name: String,
  phone: String,
  password: String,
  role: String
});

const Complaint = mongoose.model("Complaint", complaintSchema);
const User = mongoose.model("User", userSchema);

/* ================= SMART FUNCTIONS ================= */

function autoAssign(issue) {
  const text = issue.toLowerCase();

  if (text.includes("water")) return "Water Department";
  if (text.includes("road")) return "Civil Department";
  if (text.includes("electric")) return "Electricity Department";
  if (text.includes("garbage")) return "Sanitation Team";

  return "General Officer";
}

function detectPriority(issue) {
  const text = issue.toLowerCase();

  if (
    text.includes("fire") ||
    text.includes("accident") ||
    text.includes("hospital") ||
    text.includes("danger") ||
    text.includes("urgent")
  ) return "High";

  return "Normal";
}

/* ================= REGISTER CITIZEN ================= */

app.post("/register", async (req,res)=>{
  const { name, phone, password } = req.body;

  const existing = await User.findOne({ phone });
  if(existing) return res.send("Phone already registered");

  const hash = await bcrypt.hash(password,10);

  await User.create({
    name,
    phone,
    password: hash,
    role: "citizen"
  });

  res.send("Registration successful");
});

/* ================= LOGIN ================= */

app.post("/login", async (req,res)=>{
  const { phone, password, role } = req.body;

  const user = await User.findOne({ phone, role });
  if(!user) return res.send("User not found");

  const match = await bcrypt.compare(password, user.password);
  if(!match) return res.send("Wrong password");

  req.session.user = {
    id: user._id,
    role: user.role,
    name: user.name
  };

  res.send("Login successful");
});

app.get("/logout",(req,res)=>{
  req.session.destroy();
  res.send("Logged out");
});

/* ================= AUTH CHECK ================= */

function isLoggedIn(req,res,next){
  if(req.session.user) next();
  else res.status(401).send("Unauthorized");
}

function isAdmin(req,res,next){
  if(req.session.user && req.session.user.role === "admin") next();
  else res.status(403).send("Admin only");
}

/* ================= CREATE COMPLAINT ================= */

app.post("/complaints", isLoggedIn, upload.single("photo"), async (req,res)=>{

  const complaint = new Complaint({
    citizen_name: req.session.user.name,
    issue: req.body.issue,
    ward: req.body.ward,
    assigned_to: autoAssign(req.body.issue),
    priority: detectPriority(req.body.issue),
    status: "Assigned",
    photo: req.file ? req.file.filename : null
  });

  await complaint.save();

  io.emit("newComplaint");

  res.send(complaint);
});

/* ================= GET COMPLAINTS ================= */

app.get("/complaints", isLoggedIn, async (req,res)=>{

  if(req.session.user.role === "admin"){
    const data = await Complaint.find().sort({ created_at:-1 });
    return res.send(data);
  }

  const data = await Complaint.find({
    citizen_name: req.session.user.name
  }).sort({ created_at:-1 });

  res.send(data);
});

/* ================= UPDATE STATUS ================= */

app.put("/complaints/:id/status", isAdmin, async (req,res)=>{
  const updated = await Complaint.findByIdAndUpdate(
    req.params.id,
    { status: req.body.status },
    { new: true }
  );

  io.emit("statusUpdated");

  res.send(updated);
});

/* ================= SOCKET ================= */

io.on("connection", () => {
  console.log("User connected");
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 5000;

server.listen(PORT, () =>
  console.log("Server running on port " + PORT)
);