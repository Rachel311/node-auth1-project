const User = require('../users/users-model');
const db = require('../../data/db-config');


function restricted(req, res, next) {
  if (req.session.user) {
    next()
  } else {
    next({ status: 401, message: 'You shall not pass!' })
  }
}


async function checkUsernameFree(req, res, next) {
  try {
    const { username } = req.body;
    const exist = await User.findBy({ username });
    if (exist.length >= 1) {
      next({
        status: 422, message: 'Username taken'
      });
      } else {
        next();
      }
    } catch (err) {
      next(err);
    }
  }



async function checkUsernameExists(req, res, next) {
  try {
    const { username } = req.body;
    const exist = await User.findBy({ username });
    if (!exist) {
      next({
        status: 401, message: 'Invalid credentials'
      });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
};


async function checkPasswordLength(req, res, next) {
  try {
    const { password } = req.body;
    if (!password || password.length <= 3) {
      next({
        status: 422, message: 'Password must be longer than 3 chars'
      });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
}


module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
};