// test saml assertion instead of going out to IDP

const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

const app = express();

// SAML Strategy configuration
passport.use(new SamlStrategy(
    {
        path: '/login/callback',
        entryPoint: 'https://example-saml-provider.com/sso/login',
        issuer: 'your-app-identifier',
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

