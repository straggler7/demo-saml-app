const express = require("express");
const fs = require("fs");
const path = require("path");
const passport = require("passport");
const SamlStrategy = require("passport-saml").Strategy;
const xml2js = require("xml2js");

const app = express();
const port = 4000;

// Dummy certificate for validation
// const idpCert = `-----BEGIN CERTIFICATE-----
// YOUR_IDP_CERTIFICATE_HERE
// -----END CERTIFICATE-----`;

const idpCert = fs.readFileSync("okta-idp.cert");

// Passport SAML Strategy
passport.use(
  new SamlStrategy(
    {
      cert: idpCert, // Normally from IdP
      issuer: "http://localhost:4000",
      callbackUrl: "http://localhost:4000/login/callback",
    },
    (profile, done) => {
      return done(null, profile);
    }
  )
);

app.use(passport.initialize());

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

// Middleware for conditionally mocking authentication
if (process.env.NODE_ENV === 'development' || process.env.MOCK_AUTH === 'true') {
  app.use(mockAuthMiddleware);
}

// Middleware to parse XML
const parseXML = async (filePath) => {
  const xmlContent = fs.readFileSync(filePath, "utf8");
  const parser = new xml2js.Parser({ explicitArray: false });
  return await parser.parseStringPromise(xmlContent);
};

// Route: Simulate SAML Assertion Processing
app.get("/test-saml", async (req, res) => {
  try {
    // Step 1: Read SAML assertion from file
    const samlFilePath = path.join(__dirname, "test-saml-response.xml");
    const samlResponse = fs.readFileSync(samlFilePath, "utf8");
    console.log('SAML Response ---------')
    console.log(samlResponse);

    // Step 2: Pass the SAML response to the strategy for validation
    const samlStrategy = passport._strategy("saml");
    console.log('check here --------')
    console.log(samlStrategy._saml);
    console.log(samlStrategy);
    // samlStrategy._saml.validatePostResponse(
    console.log(samlStrategy._verify.toString());
    samlStrategy._verify(
      { SAMLResponse: samlResponse },
      (err, profile) => {
        if (err) {
          console.error("Error validating SAML response:", err);
          return res.status(400).send("Invalid SAML response.");
        }

        // Step 3: Display the extracted SAML profile
        res.json({
          message: "SAML assertion validated successfully!",
          user: profile,
        });
      }
    );
  } catch (err) {
    console.error("Error reading SAML file:", err);
    res.status(500).send("Internal server error.");
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
