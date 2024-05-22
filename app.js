const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const readline = require('readline');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Middleware to parse URL-encoded form data
app.use(express.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static('public'));

app.get('/',(req,res) =>{
  res.sendFile(__dirname+"/views/signup.html");
});

app.get('/login',(req,res) =>{
  res.sendFile(__dirname+"/views/login.html");
});

app.get('/home',(req,res) =>{
  res.sendFile(__dirname+"/views/index.html");
});

app.post('/signup', (req, res) => {
  const { email, password } = req.body;

  // Check if user already exists
  const users = [];
  fs.createReadStream('users.csv')
    .pipe(csv())
    .on('data', (row) => {
      users.push(row);
    })
    .on('end', () => {
      const userExists = users.some(user => user.email === email);
      if (userExists) {
        return res.send('User already exists');
      }

      // Hash password and store user data
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          return res.status(500).send('Error hashing password');
        }
        fs.appendFileSync('users.csv', `${email},${hash}\n`);
        res.redirect('/login');
      });
    });
});

// Route to handle user login


// Route to handle user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  let userFound = false;

  const rl = readline.createInterface({
    input: fs.createReadStream('users.csv'),
    output: process.stdout,
    terminal: false
  });

  for await (const line of rl) {
    const [storedEmail, hashedPassword] = line.split(',');
    if (email === storedEmail) {
      userFound = true;
      // Compare hashed password
      const result = await bcrypt.compare(password, hashedPassword);
      if (result) {
        // Redirect to home page if email and password match
        return res.redirect('/home');
      } else {
        // If password doesn't match, send appropriate response
        return res.send('Invalid email or password');
      }
    }
  }

  // If user not found, send appropriate response
  if (!userFound) {
    return res.send('User not found');
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
