require('dotenv').config();
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = '$2b$10$H0XYgFZuLhE/drO0S3vSVupID5VP5EakmtpmFxIu20znlXQRkXmcS'; // Update with your actual hash

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));
app.use(express.static(path.join(__dirname, 'public')));

// JSON file storage
const LISTINGS_FILE = path.join(__dirname, 'listings.json');

// Load listings from file or initialize empty array
let listings = [];
if (fs.existsSync(LISTINGS_FILE)) {
    listings = JSON.parse(fs.readFileSync(LISTINGS_FILE, 'utf8'));
}

// Function to save listings to file
function saveListings() {
    fs.writeFileSync(LISTINGS_FILE, JSON.stringify(listings, null, 2));
}

// Multer for Image Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
        cb(null, 'uploads');
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// JWT Verification
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

// Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    console.log('Login attempt:', username);
    if (username !== ADMIN_USERNAME || !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
        console.error('Invalid login attempt for:', username);
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    console.log('Generated token:', token);
    res.json({ token });
});

// Admin CRUD Routes
app.post('/api/admin/listings', verifyToken, upload.single('image'), (req, res) => {
    try {
        const { section, title, description, priceOrValue } = req.body;
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';
        const newListing = { id: Date.now().toString(), section, title, description, priceOrValue, imageUrl };
        listings.push(newListing);
        saveListings();
        res.json(newListing);
    } catch (err) {
        console.error('POST error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/listings', verifyToken, (req, res) => {
    res.json(listings);
});

app.get('/api/admin/listings/:id', verifyToken, (req, res) => {
    const listing = listings.find(l => l.id === req.params.id);
    if (!listing) return res.status(404).json({ message: 'Not found' });
    res.json(listing);
});

app.put('/api/admin/listings/:id', verifyToken, upload.single('image'), (req, res) => {
    try {
        const { section, title, description, priceOrValue } = req.body;
        const index = listings.findIndex(l => l.id === req.params.id);
        if (index === -1) return res.status(404).json({ message: 'Not found' });
        listings[index] = {
            ...listings[index],
            section, title, description, priceOrValue,
            imageUrl: req.file ? `/uploads/${req.file.filename}` : listings[index].imageUrl
        };
        saveListings();
        res.json(listings[index]);
    } catch (err) {
        console.error('PUT error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/listings/:id', verifyToken, (req, res) => {
    try {
        listings = listings.filter(l => l.id !== req.params.id);
        saveListings();
        res.json({ message: 'Deleted' });
    } catch (err) {
        console.error('DELETE error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Public Listings Route
app.get('/api/listings/:section', (req, res) => {
    const filtered = listings.filter(l => l.section === req.params.section);
    res.json(filtered);
});

// Inquiry Route
app.post('/api/inquiry', async (req, res) => {
    try {
        const { listingTitle, email } = req.body;
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: `Inquiry for ${listingTitle}`,
            text: `New inquiry from ${email} for ${listingTitle}`
        });
        res.json({ message: 'Inquiry sent' });
    } catch (err) {
        console.error('Inquiry error:', err);
        res.status(500).json({ message: 'Failed to send inquiry' });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));