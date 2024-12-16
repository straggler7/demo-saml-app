const express = require("express");
const passport = require("passport");
const fs = require('fs');
const xml2js = require('xml2js');
const SamlStrategy = require("passport-saml").Strategy;

const app = express();
const port = 3001;

// Configure passport to use SAML strategy
// passport.use(
//   new SamlStrategy(
//     {
//       path: "/login/callback", // URL for the IdP to send the response to
//       entryPoint: "https://idp.example.com/idp/profile/SAML2/Redirect/SSO", // IdP URL
//       issuer: "saml-demo-app", // The EntityID for your app (it could be any unique string)
//       cert: `MIID...`, // Public cert of the Identity Provider (IdP)
//     },
//     (profile, done) => {
//       // This function is called after successful authentication.
//       // You can store user profile info in your session here.
//       return done(null, profile);
//     }
//   )
// );

// SAML Configuration
const samlOptions = {
  path: "/login/callback", // The callback URL where the IdP will send the SAML response
  entryPoint: "https://dev-44283504.okta.com/app/dev-44283504_demosamlapp_1/exklwj5n42kyzrQ6W5d7/sso/saml", // Shibboleth IdP SSO URL
  issuer: "demo-saml-app", // Issuer is your Service Provider's URL
  // cert: fs.readFileSync("idp-cert.pem", "utf-8"), // Certificate from the IdP
  cert: fs.readFileSync("okta-idp.cert", "utf-8"), // Certificate from the IdP
  // privateCert: fs.readFileSync("sp-private-key.pem", "utf-8"), // Your private key for signing
  // decryptionPvk: fs.readFileSync("sp-decryption-key.pem", "utf-8"), // (Optional) If using encrypted assertions
  // acceptedClockSkewMs: -1, // Optional: Allow no clock skew
};

// Passport SAML strategy
passport.use(
  new SamlStrategy(samlOptions, (profile, done) => {
    // You can process the SAML profile here (e.g., store user info)
    console.log("SAML profile", profile);
    return done(null, profile);
  })
);

// Express middleware
app.use(passport.initialize());

app.get("/", (req, res) => {
  res.status(200).send("Hello World");
});

// SSO login route
app.get("/login", (req, res, next) => {
  passport.authenticate("saml")(req, res, next);
});

// Callback route where the IdP will redirect after successful authentication
app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/"); // Redirect to a protected route after successful login
  }
);

// Metadata endpoint - generates SAML metadata XML
app.get("/metadata", (req, res) => {
  const metadata = generateSAMLMetadata();
  res.type("xml").send(metadata);
});

// Function to generate SAML Metadata XML
function generateSAMLMetadata() {
  const spEntityID = "https://yourapp.example.com";
  const assertionConsumerServiceURL =
    "https://yourapp.example.com/login/callback";
  const metadataXml = {
    EntityDescriptor: {
      $: {
        xmlns: "urn:oasis:names:tc:SAML:2.0:metadata",
        entityID: spEntityID,
      },
      SPSSODescriptor: {
        $: {
          AuthnRequestsSigned: "false",
          WantAssertionsSigned: "true",
          protocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        AssertionConsumerService: {
          $: {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location: assertionConsumerServiceURL,
            index: "0",
          },
        },
      },
    },
  };

  const builder = new xml2js.Builder();
  return builder.buildObject(metadataXml);
}

// Start the server
app.listen(port, () => {
  console.log(`SAML SSO app listening at http://localhost:${port}`);
});
