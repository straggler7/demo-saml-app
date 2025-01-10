const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

passport.use(new SamlStrategy(
  {
    // SP settings
    entryPoint: 'https://idp.example.com/sso',
    issuer: 'https://your-app.example.com/saml/metadata',
    callbackUrl: 'https://your-app.example.com/saml/callback',
    cert: 'IdP_PUBLIC_CERTIFICATE', // Replace with your IdP's public certificate
    privateCert: 'SP_PRIVATE_CERTIFICATE', // Replace with your SP private certificate if required

    // NameID configuration
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', // or another format as required
    decryptionPvk: 'SP_DECRYPTION_PRIVATE_KEY', // Optional, for encrypted NameID

    // Additional settings
    validateInResponseTo: true,
    disableRequestedAuthnContext: false,
    additionalParams: {},
    additionalAuthorizeParams: {},
    acceptedClockSkewMs: -1,
  },
  (profile, done) => {
    // Process the SAML assertion and map the NameID
    const user = {
      id: profile.nameID, // NameID is extracted from the assertion
      email: profile.email || profile['urn:oid:0.9.2342.19200300.100.1.3'], // Example attribute for email
    };

    done(null, user);
  }
));
