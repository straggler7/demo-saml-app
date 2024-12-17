// test saml assertion instead of going out to IDP

const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const fs = require("fs");

const app = express();
const port = 4000;

process.env.MOCK_AUTH = true;

// SAML Strategy configuration
passport.use(new SamlStrategy(
    {
        path: '/login/callback',
        entryPoint: 'https://example-saml-provider.com/sso/login',
        issuer: 'your-app-identifier',
        cert: fs.readFileSync("okta-idp.cert", "utf-8"), // Public certificate of the Identity Provider (IDP)
    },
    function(profile, done) {
        // Validate and serialize user
        return done(null, profile);
    }
));

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Middleware for session handling
app.use(require('express-session')({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

const mockAuthMiddleware = (req, res, next) => {
  // Check if MOCK_AUTH is enabled
  if (process.env.MOCK_AUTH === 'true') {
      req.isAuthenticated = () => true; // Mock isAuthenticated to always return true
      req.user = { id: '12345', username: 'mockuser', email: 'mock@user.com' }; // Mock user object
  }
  next();
};

// Apply the mock middleware
if (process.env.MOCK_AUTH === 'true') {
  console.log('Mock Authentication Enabled');
  app.use(mockAuthMiddleware);
}

// Route to initiate SAML login
app.get('/login', passport.authenticate('saml'));

// Callback route after SAML authentication
app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/' }),
    (req, res) => res.redirect('/profile')
);

// Example protected route
app.get('/profile', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ user: req.user });
    } else {
        res.status(401).json({ message: 'Not Authenticated' });
    }
});

// Start the server
app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
