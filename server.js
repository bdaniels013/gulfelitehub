const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key'; // Change this to a strong secret
const ADMIN_USERNAME = 'admin'; // Your admin username
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('your-password', 10); // Change 'your-password' and hash it

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads')); // Serve uploaded images

// Connect to MongoDB
mongoose.connect('your-mongodb-connection-string', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Listing Schema (example for Business Listings; duplicate for other sections like Real Estate, Art, etc.)
const listingSchema = new mongoose.Schema({
  section: String, // e.g., 'business', 'real-estate', 'art'
  title: String,
  description: String,
  priceOrValue: String,
  imageUrl: String,
});
const Listing = mongoose.model('Listing', listingSchema);

// Multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
    cb(null, 'uploads');
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// Middleware to verify JWT (for admin routes)
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// Admin Login Route
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USERNAME || !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Admin Routes for Managing Listings (CRUD)
app.post('/api/admin/listings', verifyToken, upload.single('image'), async (req, res) => {
  const { section, title, description, priceOrValue } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';
  const listing = new Listing({ section, title, description, priceOrValue, imageUrl });
  await listing.save();
  res.json(listing);
});

app.get('/api/admin/listings', verifyToken, async (req, res) => {
  const listings = await Listing.find();
  res.json(listings);
});

app.put('/api/admin/listings/:id', verifyToken, upload.single('image'), async (req, res) => {
  const { section, title, description, priceOrValue } = req.body;
  const updateData = { section, title, description, priceOrValue };
  if (req.file) updateData.imageUrl = `/uploads/${req.file.filename}`;
  const listing = await Listing.findByIdAndUpdate(req.params.id, updateData, { new: true });
  res.json(listing);
});

app.delete('/api/admin/listings/:id', verifyToken, async (req, res) => {
  await Listing.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deleted' });
});

// Public Routes for Frontend to Fetch Listings
app.get('/api/listings/:section', async (req, res) => {
  const listings = await Listing.find({ section: req.params.section });
  res.json(listings);
});

// Serve your static frontend files (put your HTML/CSS/JS in a /public folder)
app.use(express.static(path.join(__dirname, 'public')));

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
