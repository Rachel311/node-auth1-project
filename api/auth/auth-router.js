const router = require('express').Router();
const bcrypt = require('bcryptjs');
const User = require('../users/users-model');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware');


router.post('/register', checkUsernameExists, checkPasswordLength, async (req, res, next) => {
  try {
    const {username, password } = req.body
    const hash = bcrypt.hashSync(password, 8)
    const newUser = { username, password: hash }
    const user = await User.add(newUser);
    res.status(200).json(this.user);
  } catch (err) {
    next(err);
  }
})

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body
    const [existingUser] = await User.findBy({ username })
    if (existingUser && bcrypt.compareSync(password, existingUser.password)) {
      req.session.user = existingUser
      res.json({ status: 200, message: `welcome, ${existingUser.username}!`})
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err);
  }
})

router.get('logout', async (req, res, next) => {
  if (req.session.user) {
    req.session.destroy(err => {
      if (err) {
        res.json({ message: 'cannot log out'})
      } else {
        res.json({ message: 'logged out'})
      }
    })
  } else {
    res.json({ message: 'no session'})
  }
})


module.exports = router;






/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
