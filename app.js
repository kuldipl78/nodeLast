const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const databasePath = path.join(__dirname, 'twitterClone.db')

const app = express()

app.use(express.json())

let db = null

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    })

    app.listen(3000, () =>
      console.log('Server Running at http://localhost:3000/'),
    )
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}

initializeDbAndServer()

app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body
  const passGetQuery = `SELECT * FROM User WHERE username = ?`
  try {
    const dbResponse = await db.get(passGetQuery, [username])
    if (dbResponse !== undefined) {
      response.status(400).send('User already exists')
    } else if (password.length < 6) {
      response.status(400).send('Password is too short')
    } else {
      const hashedPassword = await bcrypt.hash(password, 10)
      const addDataQuery = `INSERT INTO User (name, username, password, gender) VALUES (?, ?, ?, ?)`
      await db.run(addDataQuery, [name, username, hashedPassword, gender])
      response.status(200).send('User created successfully')
    }
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

// Middleware for JWT authentication
const authenticateJWT = (request, response, next) => {
  const token = request.headers.authorization
  if (!token) {
    return response.status(401).json({message: 'Invalid JWT Token'})
  }
  jwt.verify(token, 'MY_SECRET_KEY', (err, decoded) => {
    if (err) {
      return response.status(401).json({message: 'Invalid JWT Token'})
    }
    request.user = decoded
    next()
  })
}

// Login API
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const selectUserQuery = `SELECT * FROM User WHERE username = ?`
  try {
    const dataBaseUser = await db.get(selectUserQuery, [username])
    if (!dataBaseUser) {
      response.status(400).send('Invalid user')
    } else {
      const ispassMatch = await bcrypt.compare(password, dataBaseUser.password)
      if (ispassMatch) {
        const payload = {user_id: dataBaseUser.user_id}
        const jwtToken = jwt.sign(payload, 'MY_SECRET_KEY')
        response.json({jwtToken})
      } else {
        response.status(400).send('Invalid password')
      }
    }
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

// Protected route example
app.get('/protected', authenticateJWT, (request, response) => {
  response.send('You are authorized')
})

// API 3: Get user's tweet feed
app.get('/user/tweets/feed/', authenticateJWT, async (request, response) => {
  const userId = request.user.user_id // Extract user_id from JWT token payload
  try {
    // Query to get latest tweets of people whom the user follows
    const tweetFeedQuery = `
      SELECT u.username, t.tweet, t.date_time AS dateTime
      FROM tweet AS t
      INNER JOIN follower AS f ON t.user_id = f.following_user_id
      INNER JOIN user AS u ON t.user_id = u.user_id
      WHERE f.follower_user_id = ?
      ORDER BY t.date_time DESC
      LIMIT 4
    `
    const tweets = await db.all(tweetFeedQuery, [userId])
    response.json(tweets)
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

module.exports = app
