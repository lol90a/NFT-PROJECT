/*
Project : Cryptotrades
FileName : adminauth.js
Author : LinkWell
File Created : 21/07/2021
CopyRights : LinkWell
Purpose : This is the file which checks whether a user is authorized or not to use the Admin API.
*/

const jwt = require('jsonwebtoken');
const config = require('./../helper/config');
const logger = require('./../helper/logger'); // Assumed logger for structured logging
const rateLimit = require('express-rate-limit'); // Rate limiting to prevent brute force attacks
const moment = require('moment'); // For better date/time handling

// Security enhancement: Helmet middleware for secure HTTP headers
const helmet = require('helmet');

// Importing constants and helper functions for enhanced flexibility and maintainability
const { ADMIN_ROLE, TOKEN_EXPIRATION_BUFFER } = require('./../helper/constants');
const { extractToken, isTokenBlacklisted } = require('./../helper/tokenHelper');

// Middleware for applying HTTP security headers
const applySecurityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  frameguard: {
    action: 'deny', // Prevent clickjacking attacks
  },
  hsts: {
    maxAge: 31536000, // 1 year, for enforcing HTTPS
  },
  noSniff: true, // Prevent MIME-type sniffing
  xssFilter: true, // Basic XSS protection
});

// Middleware for rate limiting requests to the API
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    status: false,
    message: 'Too many requests, please try again later.',
  },
  headers: true, // Add rate limit info in response headers
});

// Function to enhance token verification and decode the payload
function verifyAndDecodeToken(token, secretKey) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
}

// Advanced middleware for admin authorization
let adminauth = async (req, res, next) => {
  try {
    // Extract the token from the request headers
    let token = req.headers['x-access-token'] || req.headers['authorization'];
    
    if (!token) {
      logger.warn('Auth token not provided', { ip: req.ip, path: req.originalUrl });
      return res.status(401).json({
        status: false,
        message: 'Auth token is not supplied',
      });
    }

    // Remove 'Bearer ' prefix if present
    token = extractToken(token);

    // Check if the token is blacklisted (e.g., logged-out users or revoked tokens)
    const isBlacklisted = await isTokenBlacklisted(token);
    if (isBlacklisted) {
      logger.warn('Blacklisted token used', { token, ip: req.ip, path: req.originalUrl });
      return res.status(403).json({
        status: false,
        message: 'Token is blacklisted, please log in again.',
      });
    }

    // Verify and decode the token
    let decoded;
    try {
      decoded = await verifyAndDecodeToken(token, config.secret_key);
    } catch (error) {
      logger.error('Invalid token verification', { error: error.message, ip: req.ip, path: req.originalUrl });
      return res.status(403).json({
        status: false,
        message: 'Token is not valid',
        error: error.message, // Provide error message for easier debugging
      });
    }

    // Check if the decoded token contains an admin role
    if (decoded.role !== ADMIN_ROLE) {
      logger.warn('Unauthorized access attempt', { userId: decoded.id, ip: req.ip, path: req.originalUrl });
      return res.status(403).json({
        status: false,
        message: "Access denied. You don't have permission to access this endpoint.",
      });
    }

    // Check if the token has expired
    const currentTime = moment().unix();
    if (decoded.exp < currentTime) {
      logger.warn('Expired token used', { userId: decoded.id, exp: decoded.exp, ip: req.ip });
      return res.status(401).json({
        status: false,
        message: 'Token has expired, please log in again.',
      });
    }

    // Optional: Add buffer time to handle cases where tokens are close to expiring
    if (decoded.exp - currentTime < TOKEN_EXPIRATION_BUFFER) {
      logger.info('Token nearing expiration', { userId: decoded.id, remainingTime: decoded.exp - currentTime });
    }

    // Log user activity for auditing
    logger.info('Admin access granted', { userId: decoded.id, ip: req.ip, path: req.originalUrl });

    // Attach the decoded token payload to the request object
    req.decoded = decoded;

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    logger.error('Error in adminauth middleware', { error: error.message, ip: req.ip, path: req.originalUrl });
    return res.status(500).json({
      status: false,
      message: 'Internal Server Error',
      error: error.message,
    });
  }
};

module.exports = {
  adminauth,
  limiter,
  applySecurityHeaders,
};


