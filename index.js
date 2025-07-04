import express from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid'; 
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// --- MongoDB Connection ---
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- User Schema and Model ---
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

// Pre-save hook to hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare passwords
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

let products = [
  {
    id: '1',
    title: "Wireless Headphones",
    description: "Noise cancelling over-ear headphones with deep bass.",
    image: "https://res.cloudinary.com/da3w329cx/image/upload/v1683056487/samples/landscapes/nature-mountains.jpg",
    price: 120,
  },
  {
    id: '2',
    title: "Smart Watch",
    description: "Smart wearable with health tracking, notifications, and long battery life.",
    image: "https://res.cloudinary.com/da3w329cx/image/upload/v1683056500/cld-sample-5.jpg",
    price: 80,
  },
  {
    id: '3',
    title: "Laptop",
    description: "14-inch Full HD display, 256GB SSD, 8GB RAM. Perfect for productivity.",
    image: "https://res.cloudinary.com/da3w329cx/image/upload/v1683056499/cld-sample-3.jpg",
    price: 600,
  },
];

// --- JWT Token Generation Helper ---
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '1h', // Token expires in 1 hour
  });
};

// --- Auth Routes ---

// POST /api/auth/register - Register a new user
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, phone, password } = req.body;

  if (!fullName || !email || !phone || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = await User.create({
      fullName,
      email,
      phone,
      password, // Password will be hashed by the pre-save hook
    });

    if (user) {
      res.status(201).json({
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        token: generateToken(user._id), // Return JWT
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
});

// POST /api/auth/login - Authenticate user & get token
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }

  try {
    const user = await User.findOne({ email });

    if (user && (await user.matchPassword(password))) {
      res.status(200).json({
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        token: generateToken(user._id), // Return JWT
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' }); // 401 Unauthorized
    }
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
});

// --- Product Routes (using in-memory array as per your current setup) ---

// GET /api/products - Get all products
app.get('/api/products', (req, res) => {
  res.status(200).json(products);
});

// GET /api/products/:id - Get one product
app.get('/api/products/:id', (req, res) => {
  const { id } = req.params;
  const product = products.find(p => p.id === id);

  if (product) {
    res.status(200).json(product);
  } else {
    res.status(404).json({ message: 'Product not found' });
  }
});

// POST /api/products - Add a product
app.post('/api/products', (req, res) => {
  const { title, image, description, price } = req.body;

  if (!title || !image || !description || !price) {
    return res.status(400).json({ message: 'Please provide all required fields: title, image, description, price' });
  }
  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ message: 'Price must be a positive number' });
  }

  const newProduct = {
    id: uuidv4(),
    title,
    image,
    description,
    price,
  };

  products.push(newProduct);
  res.status(201).json(newProduct);
});

// PUT /api/products/:id - Update a product
app.put('/api/products/:id', (req, res) => {
  const { id } = req.params;
  const { title, image, description, price } = req.body;

  let productFound = false;
  products = products.map(product => {
    if (product.id === id) {
      productFound = true;
      if (!title || !image || !description || !price) {
        return res.status(400).json({ message: 'Please provide all required fields: title, image, description, price for update' });
      }
      if (typeof price !== 'number' || price <= 0) {
        return res.status(400).json({ message: 'Price must be a positive number' });
      }
      return { ...product, title, image, description, price };
    }
    return product;
  });

  if (productFound) {
    const updatedProduct = products.find(p => p.id === id);
    res.status(200).json(updatedProduct);
  } else {
    res.status(404).json({ message: 'Product not found' });
  }
});

// DELETE /api/products/:id - Delete a product
app.delete('/api/products/:id', (req, res) => {
  const { id } = req.params;
  const initialLength = products.length;
  products = products.filter(p => p.id !== id);

  if (products.length < initialLength) {
    res.status(200).json({ message: 'Product deleted successfully' });
  } else {
    res.status(404).json({ message: 'Product not found' });
  }
});

// Server Start
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});