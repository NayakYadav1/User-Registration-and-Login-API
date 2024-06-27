// Importing required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Creating an Express application instance
const app = express();
app.use(express.json())
const port = 3000;

// Connect to MongoDB database
mongoose.connect('mongodb://localhost:27017/UserAuthentication')
.then(() => {
    console.log('Successfully connected to the database');
})
.catch((err) => {
    console.error('Error connecting to the database', err);
})

// Define schema for the user collection
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String
});

// Creating user model based on schema
const User = mongoose.model('User', userSchema);

// Middleware to parse json bodies
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if(!token){
        return res.status(401).json({error: 'Unauthorized'});
    }

    jwt.verify(token, 'secret', (err, decoded) => {
        if(err){
            return res.status(401).json({error: 'Unauthorized'});
        }
        req.user = decoded;
        next();
    });
};

// Route to register a new user
app.post('/api/register', async(req, res) => {
    try{
        // Check if the email already exist
        const existingUser = await User.findOne({ email: req.body.email });
        if(existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        
        // Hash the password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Create new user
        const newUser = new User ({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword
        })

        await newUser.save();


        res.status(201).json({ message: 'User created successfully' });
    } catch(error) {
        res.status(500).json({ error: 'Internal Server Error'});
    }
});

// Route to authenticate and login a user
app.post('/api/login', async(req, res) => {
    try{
        // Check if the email exists
        const user = await User.findOne({ email: req.body.email});
        if(!user) {
            return res.status(401).json({ error: 'No User exists' });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(req.body.password, user.password);
        if(!passwordMatch){
            return res.status(401).json({ error: 'Invalid Credentials'});
        }

        // Generate JWT Token
        const token = jwt.sign({email: user.email}, 'secret');
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Protected route to get user details
app.get('/api/user', verifyToken, async(req, res) => {
    try{
        // Fetch user details using decoded token
        const user = await User.findOne({email: req.user.email});
        if(!user){
            return res.status(404).json('User not found!!!');
        }
        res.status(200).json({ username: user.username, email: user.email });
    } catch(error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Default route
app.get('/', (req, res) => {
    res.send('Welcome to the User Registration and Login API');
});

app.listen(port, () => {
    console.log(`Server successfully started on port ${port}`);
});

