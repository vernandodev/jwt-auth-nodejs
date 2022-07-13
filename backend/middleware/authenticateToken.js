const jwt = require('jsonwebtoken');
require('dotenv').config();

const authToken = async (res, req, next) => {
  // Option 1
  // const authHeader = req.headers['authorization'];
  // const token = authHeader && authHeader.split(' ')[1];

  // Option 2
  const token = req.header('x-auth-token');

  // if token not found , send error message
  if (!token) {
    res.status(401).json({
      errors: [
        {
          message: 'Token Not Found !',
        },
      ],
    });
  }

  // Authenticate token
  try {
    const user = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = user.email();
    next();
  } catch (e) {
    res.status(403).json({
      errors: [
        {
          message: 'Invalid token',
        },
      ],
    });
  }
};

module.exports = authToken;
