const SamlStrategy = require('passport-saml').Strategy;

passport.use(new SamlStrategy(
  {
    entryPoint: 'https://idp.example.com/sso',
    issuer: 'https://your-app.example.com/saml/metadata',
    callbackUrl: 'https://your-app.example.com/saml/callback',
    cert: 'IdP_PUBLIC_CERTIFICATE',
    privateCert: 'SP_PRIVATE_CERTIFICATE',
    decryptionPvk: 'SP_PRIVATE_KEY',
    validateInResponseTo: true,
    disableRequestedAuthnContext: false,
    acceptedClockSkewMs: 1000 * 60,
    debug: true, // Enable debugging logs
  },
  (profile, done) => {
    done(null, profile);
  }
));
