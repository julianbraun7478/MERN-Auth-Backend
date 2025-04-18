const User = require('../models/auth.model');
const { OAuth2Client } = require('google-auth-library');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const _ = require('lodash');
const { errorHandler } = require('../helpers/dbErrorHandling');
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.MAIL_KEY);

const client = new OAuth2Client(process.env.GOOGLE_CLIENT);

// Register Controller
exports.registerController = async (req, res) => {
  const { name, email, password } = req.body;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const firstError = errors.array()[0].msg;
    return res.status(422).json({ errors: firstError });
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ errors: 'Email is taken' });
  }

  const token = jwt.sign({ name, email, password }, process.env.JWT_ACCOUNT_ACTIVATION, { expiresIn: '5m' });

  const emailData = {
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Account activation link',
    html: `
      <h1>Please use the following to activate your account</h1>
      <p>${process.env.CLIENT_URL}/users/activate/${token}</p>
      <hr />
      <p>This email may contain sensitive information</p>
      <p>${process.env.CLIENT_URL}</p>
    `
  };

  try {
    await sgMail.send(emailData);
    return res.json({ message: `Email has been sent to ${email}` });
  } catch (err) {
    return res.status(400).json({ success: false, errors: errorHandler(err) });
  }
};

// Activation Controller
exports.activationController = async (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(400).json({ message: 'Token is missing' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION);
    const { name, email, password } = decoded;

    const user = new User({ name, email, password });
    await user.save();

    return res.json({ success: true, message: 'Signup success' });
  } catch (err) {
    return res.status(401).json({ errors: 'Expired link. Signup again' });
  }
};

// Signin Controller
exports.signinController = async (req, res) => {
  const { email, password } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array()[0].msg });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !user.authenticate(password)) {
      return res.status(400).json({ errors: 'Email and password do not match or user does not exist' });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const { _id, name, role } = user;

    return res.json({ token, user: { _id, name, email, role } });
  } catch (err) {
    return res.status(400).json({ errors: errorHandler(err) });
  }
};

// Middleware to protect routes
exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET,
  algorithms: ['HS256'],
  userProperty: 'user',
});

// Admin middleware
exports.adminMiddleware = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin resource. Access denied.' });
    }
    req.profile = user;
    next();
  } catch (err) {
    return res.status(400).json({ error: 'User not found' });
  }
};

// Forgot Password Controller
exports.forgotPasswordController = async (req, res) => {
  const { email } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array()[0].msg });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User with that email does not exist' });

    const token = jwt.sign({ _id: user._id }, process.env.JWT_RESET_PASSWORD, { expiresIn: '10m' });

    user.resetPasswordLink = token;
    await user.save();

    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Password Reset Link',
      html: `
        <h1>Reset your password</h1>
        <p>${process.env.CLIENT_URL}/users/password/reset/${token}</p>
        <hr />
        <p>${process.env.CLIENT_URL}</p>
      `,
    };

    await sgMail.send(emailData);
    res.json({ message: `Email has been sent to ${email}` });
  } catch (err) {
    return res.status(400).json({ error: 'Something went wrong. Try again.' });
  }
};

// Reset Password Controller
exports.resetPasswordController = async (req, res) => {
  const { resetPasswordLink, newPassword } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array()[0].msg });
  }

  try {
    const decoded = jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD);
    const user = await User.findOne({ resetPasswordLink });
    if (!user) return res.status(400).json({ error: 'Invalid token or user not found' });

    user.password = newPassword;
    user.resetPasswordLink = '';
    await user.save();

    return res.json({ message: 'Password reset success! You can now login.' });
  } catch (err) {
    return res.status(400).json({ error: 'Expired or invalid link. Try again.' });
  }
};

// Google Login Controller
exports.googleController = async (req, res) => {
  const { idToken } = req.body;

  try {
    const response = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT,
    });

    const { email_verified, name, email } = response.payload;
    if (!email_verified) {
      return res.status(400).json({ error: 'Google login failed. Try again' });
    }
    
    let user = await User.findOne({ email });
    console.log(user);

    if (user) {
      const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
      const { _id, role } = user;
      return res.json({ token, user: { _id, email, name, role } });
    } else {
      const password = email + process.env.JWT_SECRET;
      user = new User({ name, email, password });
      const data = await user.save();

      const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
      const { _id, role } = data;
      return res.json({ token, user: { _id, email, name, role } });
    }
  } catch (err) {
    console.log('GOOGLE LOGIN ERROR', err);
    return res.status(400).json({ error: 'Google login failed' });
  }
};

exports.facebookController = (req, res) => {
  console.log('FACEBOOK LOGIN REQ BODY', req.body);
  const { userID, accessToken } = req.body;

  const url = 'https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}';

  return (
    fetch(url, {
      method: 'GET'
    })
      .then(response => response.json())
      // .then(response => console.log(response))
      .then(response => {
        const { email, name } = response;
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: '7d'
            });
            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role }
            });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log('ERROR FACEBOOK LOGIN ON USER SAVE', err);
                return res.status(400).json({
                  error: 'User signup failed with facebook'
                });
              }
              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
              );
              const { _id, email, name, role } = data;
              return res.json({
                token,
                user: { _id, email, name, role }
              });
            });
          }
        });
      })
      .catch(error => {
        res.json({
          error: 'Facebook login failed. Try later'
        });
      })
  );
};