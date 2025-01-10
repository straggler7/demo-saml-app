const express = require('express');
const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

const app = express();
const PORT = 3000;

// Function to parse metadata synchronously
function parseMetadataSync(filePath) {
    try {
        const fileContent = fs.readFileSync(filePath, 'utf8'); // Read the file synchronously
        const parser = new xml2js.Parser();
        let metadata = null;

        parser.parseString(fileContent, (err, result) => {
            if (err) throw err;
            metadata = result;
        });

        return metadata;
    } catch (error) {
        console.error('Error reading or parsing metadata:', error);
        throw error;
    }
}

// Read and parse metadata synchronously during app startup
const metadataFilePath = path.join(__dirname, 'idp-metadata.xml');
const metadata = parseMetadataSync(metadataFilePath);

// Extract required fields from parsed metadata
const entityId = metadata.EntityDescriptor.$.entityID;
const ssoService = metadata.EntityDescriptor.IDPSSODescriptor[0].SingleSignOnService.find(
    (service) => service.$.Binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
);
const cert = metadata.EntityDescriptor.IDPSSODescriptor[0].KeyDescriptor[0].KeyInfo[0].X509Data[0].X509Certificate[0];

// Configure Passport SAML strategy
const samlStrategy = new SamlStrategy(
    {
        entryPoint: ssoService.$.Location,
        issuer: entityId,
        cert: cert,
        callbackUrl: 'http://localhost:3000/login/callback', // Update with your callback URL
        decryptionPvk: '', // Optional, if you have a private key for decryption
        privateCert: '', // Optional, if signing requests
    },
    (profile, done) => {
        // Implement user lookup or creation logic
        return done(null, profile);
    }
);

// Attach the strategy to Passport
passport.use('saml', samlStrategy);

// Initialize Passport
app.use(passport.initialize());

// Login route using SAML
app.get('/login', passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }));

// Callback route for SAML
app.post('/login/callback', passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }), (req, res) => {
    res.redirect('/success');
});

// Success route
app.get('/success', (req, res) => {
    res.send('Login successful!');
});

// Start the Express server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
