const express = require("express");
const session = require("express-session");
const passport = require("passport");
const SamlStrategy = require("passport-saml").Strategy;
const fs = require("fs");

const app = express();

// Session Configuration
app.use(
  session({
    secret: "session-secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// SAML Strategy (Real Implementation)
passport.use(
  new SamlStrategy(
    {
      entryPoint:
        "https://dev-44283504.okta.com/app/dev-44283504_demosamlapp_1/exklwj5n42kyzrQ6W5d7/sso/saml", // Replace with your IdP's SSO URL
      issuer: "demo-saml-app", // Your SP Entity ID
      callbackUrl: "http://localhost:4000/login/callback", // The callback endpoint for SAML responses
      cert: fs.readFileSync("okta-idp.cert", "utf-8"), // Public certificate of the Identity Provider (IDP)
    },

    (profile, done) => {
      return done(null, {
        id: profile.nameID,
        email: profile.email || "unknown@example.com",
        displayName: profile.displayName || "Unknown User",
      });
    }
  )
);

// Serialize and Deserialize User
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

process.env.MOCK_AUTH = true;

// Mock Authentication Middleware
const mockAuthMiddleware = (req, res, next) => {
  if (process.env.MOCK_AUTH === "true") {
    console.log("Mock Authentication Enabled");
    req.isAuthenticated = () => true;
    req.user = {
      id: "mock-user-123",
      email: "mock@user.com",
      displayName: "Mock User",
    };
    req.login(req.user, (err) => {
      if (err) return next(err);
      return res.redirect("/profile");
    });
  } else {
    next();
  }
};

// Login Route
app.get("/login", mockAuthMiddleware, passport.authenticate("saml"));

// Callback Route
app.post(
  "/login/callback",
  mockAuthMiddleware,
  passport.authenticate("saml", { failureRedirect: "/" }),
  (req, res) => res.redirect("/profile")
);

// Protected Route
app.get("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ user: req.user });
  } else {
    res.status(401).json({ message: "Not Authenticated" });
  }
});

// Start the Server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
