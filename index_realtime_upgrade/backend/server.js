const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key_here'; // Change this to a strong secret key
const usersFilePath = path.join(__dirname, 'users.json');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Load users from file
function loadUsers() {
    if (!fs.existsSync(usersFilePath)) fs.writeFileSync(usersFilePath, '[]');
    return JSON.parse(fs.readFileSync(usersFilePath));
}

// Save users to file
function saveUsers(users) {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
}

// ---------- SIGNUP ----------
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    const users = loadUsers();

    if (users.find(u => u.email === email)) {
        return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ email, password: hashedPassword });
    saveUsers(users);

    res.json({ message: 'Signup successful' });
});

// ---------- LOGIN ----------
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const users = loadUsers();

    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
});

// ---------- FORGOT PASSWORD (with Gmail support) ----------
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const users = loadUsers();

    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'User not found' });

    const resetToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: '15m' });
    const resetLink = `http://localhost:${PORT}/reset-password/${resetToken}`;

    // Configure Gmail SMTP (replace with your credentials)
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'yourgmail@gmail.com',
            pass: 'your-app-password' // Use Gmail App Password, NOT your regular password
        }
    });

    const mailOptions = {
        from: 'yourgmail@gmail.com',
        to: email,
        subject: 'Password Reset',
        text: `Click here to reset your password: ${resetLink}`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Failed to send email' });
        }
        res.json({ message: 'Password reset link sent to your email' });
    });
});

// ---------- RESET PASSWORD ----------
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const users = loadUsers();

        const user = users.find(u => u.email === decoded.email);
        if (!user) return res.status(400).json({ message: 'Invalid token or user not found' });

        user.password = await bcrypt.hash(newPassword, 10);
        saveUsers(users);

        res.json({ message: 'Password reset successful' });
    } catch (err) {
        res.status(400).json({ message: 'Invalid or expired token' });
    }
});
const frontendPath = path.join(__dirname, '../frontend');
app.use(express.static(frontendPath));

app.get('/', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
});


// ---------- START SERVER ----------
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
