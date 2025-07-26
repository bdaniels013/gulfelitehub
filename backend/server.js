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
const { v4: uuidv4 } = require('uuid'); // Added for unique IDs
const { body, validationResult } = require('express-validator'); // Added for input validation

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '$2b$10$clxwZ8D/2J2h0BFc3bvi0uOalzyz6ZhgfIOu9wZ940MG/PckmgBDC';

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '../public')));

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// JSON file storage
const LISTINGS_FILE = path.join(__dirname, 'listings.json');

// Load listings from file or initialize empty array
let listings = [];
if (fs.existsSync(LISTINGS_FILE)) {
    try {
        listings = JSON.parse(fs.readFileSync(LISTINGS_FILE, 'utf8'));
    } catch (err) {
        console.error('Error loading listings:', err);
        listings = [];
    }
}

// Function to save listings to file
function saveListings() {
    try {
        fs.writeFileSync(LISTINGS_FILE, JSON.stringify(listings, null, 2));
    } catch (err) {
        console.error('Error saving listings:', err);
    }
}

// Multer for Image Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads');
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// JWT Verification Middleware
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
app.post('/api/admin/login', [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').trim().notEmpty().withMessage('Password is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
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

// Create Listing
app.post('/api/admin/listings', verifyToken, upload.single('image'), [
    body('section').trim().notEmpty().withMessage('Section is required'),
    body('title').trim().notEmpty().withMessage('Title is required'),
    body('description').trim().notEmpty().withMessage('Description is required'),
    body('priceOrValue').trim().notEmpty().withMessage('Price or value is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { section, title, description, priceOrValue } = req.body;
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';
        const newListing = { id: uuidv4(), section, title, description, priceOrValue, imageUrl };
        listings.push(newListing);
        saveListings();
        res.status(201).json(newListing);
    } catch (err) {
        console.error('POST error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get All Listings
app.get('/api/admin/listings', verifyToken, (req, res) => {
    res.json(listings);
});

// Get Single Listing
app.get('/api/admin/listings/:id', verifyToken, (req, res) => {
    const listing = listings.find(l => l.id === req.params.id);
    if (!listing) return res.status(404).json({ message: 'Not found' });
    res.json(listing);
});

// Update Listing
app.put('/api/admin/listings/:id', verifyToken, upload.single('image'), [
    body('section').trim().notEmpty().withMessage('Section is required'),
    body('title').trim().notEmpty().withMessage('Title is required'),
    body('description').trim().notEmpty().withMessage('Description is required'),
    body('priceOrValue').trim().notEmpty().withMessage('Price or value is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { section, title, description, priceOrValue } = req.body;
        const index = listings.findIndex(l => l.id === req.params.id);
        if (index === -1) return res.status(404).json({ message: 'Not found' });
        let imageUrl = listings[index].imageUrl;
        if (req.file) {
            // Delete old image if exists
            if (imageUrl && fs.existsSync(path.join(__dirname, imageUrl))) {
                fs.unlinkSync(path.join(__dirname, imageUrl));
            }
            imageUrl = `/uploads/${req.file.filename}`;
        }
        listings[index] = { ...listings[index], section, title, description, priceOrValue, imageUrl };
        saveListings();
        res.json(listings[index]);
    } catch (err) {
        console.error('PUT error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete Listing
app.delete('/api/admin/listings/:id', verifyToken, (req, res) => {
    try {
        const index = listings.findIndex(l => l.id === req.params.id);
        if (index === -1) return res.status(404).json({ message: 'Not found' });
        const imageUrl = listings[index].imageUrl;
        if (imageUrl && fs.existsSync(path.join(__dirname, imageUrl))) {
            fs.unlinkSync(path.join(__dirname, imageUrl));
        }
        listings.splice(index, 1);
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
app.post('/api/inquiry', [
    body('listingTitle').trim().notEmpty().withMessage('Listing title is required'),
    body('email').trim().isEmail().withMessage('Valid email is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
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

// Root Route for Testing
app.get('/', (req, res) => {
    res.send('Server is running. Access /admin.html for the dashboard.');
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));