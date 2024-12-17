// app.js
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const passport = require("passport");
const SamlStrategy = require("passport-saml").Strategy;
const xmlbuilder = require("xmlbuilder");
const fs = require("fs");

const app = express();
const port = 4000;

// SAML Configuration
const samlOptions = {
  entryPoint:
    "https://dev-44283504.okta.com/app/dev-44283504_demosamlapp_1/exklwj5n42kyzrQ6W5d7/sso/saml", // Replace with your IdP's SSO URL
  issuer: "demo-saml-app", // Your SP Entity ID
  callbackUrl: "http://localhost:3000/login/callback", // The callback endpoint for SAML responses
  //   cert: "-----BEGIN CERTIFICATE-----\nYourIdPCertificate\n-----END CERTIFICATE-----", // Replace with IdP's X.509 certificate
  cert: fs.readFileSync("okta-idp.cert", "utf-8"), // Public certificate of the Identity Provider (IDP)
};

// Passport SAML Strategy
passport.use(
  new SamlStrategy(samlOptions, (profile, done) => {
    return done(null, profile);
  })
);

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: "your_secret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Serialize and deserialize users
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Routes
app.get("/", (req, res) => {
  console.log("here now...");
  if (res.isAuthenticated && res.isAuthenticated()) {
    res.send("You are already authenticated");
  }
  res.send('<a href="/login">Login with SSO</a>');
});

// Initiate SSO
app.get("/login", passport.authenticate("saml"));

// SAML callback endpoint
app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/", failureFlash: true }),
  (req, res) => {
    console.log("login callback ---------------");
    console.log("is authenticated --------------- ", req.isAuthenticated());
    // console.log(req);
    res.redirect("/profile");
  }
);

// User profile
app.get("/profile", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/");
  } else {
    console.log('In profile and authenticated!');
  }
  res.send(`<h1>Welcome, ${req.user.nameID}</h1><a href="/logout">Logout</a>`);
});

// Logout
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

// Metadata endpoint for IdP
app.get("/metadata", (req, res) => {
  const metadata = xmlbuilder
    .create("EntityDescriptor", { version: "1.0", encoding: "UTF-8" })
    .att("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata")
    .att("entityID", samlOptions.issuer);

  const spSSODescriptor = metadata.ele("SPSSODescriptor", {
    AuthnRequestsSigned: "true",
    WantAssertionsSigned: "true",
    protocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
  });

  spSSODescriptor.ele("AssertionConsumerService", {
    Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    Location: samlOptions.callbackUrl,
    index: "1",
    isDefault: "true",
  });

  spSSODescriptor
    .ele("KeyDescriptor", { use: "signing" })
    .ele("KeyInfo", { xmlns: "http://www.w3.org/2000/09/xmldsig#" })
    .ele("X509Data")
    .ele(
      "X509Certificate",
      samlOptions.cert
        .replace(/-----\w+ CERTIFICATE-----/g, "")
        .replace(/\n/g, "")
    )
    .up()
    .up()
    .up()
    .up();

  res.type("application/xml");
  res.send(metadata.end({ pretty: true }));
});

// Start the server
app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
