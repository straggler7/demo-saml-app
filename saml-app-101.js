const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const fs = require('fs');
const xml2js = require('xml2js');

// Setup Express app
const app = express();
const port = 3000;

// SAML Configuration
const samlConfig = {
    path: '/login/callback', // Callback URL after SSO
    entryPoint: 'https://your-sso-idp.com/sso', // Your SSO IDP entry point
    issuer: 'your-app-identifier', // Issuer, often your application's URL or an identifier
    cert: fs.readFileSync('path/to/your/idp-public-certificate.pem', 'utf-8'), // Public certificate of the Identity Provider (IDP)
    privateCert: fs.readFileSync('path/to/your/private-key.pem', 'utf-8'), // Private key of your service
    decryptionPvk: fs.readFileSync('path/to/your/decryption-key.pem', 'utf-8') // Optional, if the SAML response is encrypted
};

// Passport SAML strategy setup
passport.use(new SamlStrategy(samlConfig, (profile, done) => {
    // Here you would handle user authentication (e.g., create session)
    console.log('SAML Profile:', profile);
    return done(null, profile); // On success, the user's profile is returned
}));

// Initialize passport and express session (needed for authentication)
app.use(require('express-session')({ secret: 'your-secret', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Route for SAML login
app.get('/login', passport.authenticate('saml'));

// Callback route to handle the SAML response
app.post('/login/callback', passport.authenticate('saml', {
    failureRedirect: '/',
    successRedirect: '/profile'
}));

// Protected route that requires successful login
app.get('/profile', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.send(`Hello ${req.user.nameId}, welcome to your profile.`);
});

// Endpoint to download the SAML metadata
app.get('/metadata', (req, res) => {
    const metadata = generateMetadata(samlConfig);
    res.header('Content-Type', 'application/xml');
    res.send(metadata);
});

// Function to generate SAML metadata
function generateMetadata(config) {
    const entityDescriptor = {
        'EntityDescriptor': {
            $: {
                xmlns: 'urn:oasis:names:tc:SAML:2.0:metadata',
                entityID: config.issuer
            },
            'SPSSODescriptor': {
                $: {
                    AuthnRequestsSigned: 'true',
                    WantAssertionsSigned: 'true',
                    protocolSupportEnumeration: 'urn:oasis:names:tc:SAML:2.0:protocol'
                },
                'KeyDescriptor': {
                    $: {
                        use: 'signing'
                    },
                    'KeyInfo': {
                        'X509Data': {
                            'X509Certificate': fs.readFileSync(config.cert, 'utf-8').trim()
                        }
                    }
                },
                'AssertionConsumerService': {
                    $: {
                        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                        Location: `${config.issuer}${config.path}`,
                        index: 0
                    }
                }
            }
        }
    };

    // Convert the metadata object to XML
    const builder = new xml2js.Builder();
    const xml = builder.buildObject(entityDescriptor);
    return xml;
}

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
