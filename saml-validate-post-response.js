const samlStrategy = require('passport-saml').Strategy;

app.post('/saml/callback', async (req, res) => {
    try {
        // Assuming your SAML strategy instance is initialized
        const profile = await samlStrategy.validatePostResponseAsync(req.body);

        // If validation succeeds, redirect or handle login
        res.redirect('/dashboard');
    } catch (error) {
        console.error('SAML validation error:', error);

        // Redirect to a custom failure page
        res.redirect('/auth/failure');
    }
});


app.post('/saml/callback', async (req, res) => {
    try {
        const profile = await samlStrategy.validatePostResponseAsync(req.body);
        res.redirect('/dashboard');
    } catch (error) {
        let errorMessage = 'Authentication failed.';

        if (error.message.includes('Invalid signature')) {
            errorMessage = 'The response signature is invalid.';
        } else if (error.message.includes('Request ID mismatch')) {
            errorMessage = 'The SAML request could not be validated.';
        }

        res.redirect(`/auth/failure?message=${encodeURIComponent(errorMessage)}`);
    }
});

app.get('/auth/failure', (req, res) => {
    const message = req.query.message || 'An error occurred during authentication.';
    res.render('auth-failure', { message });
});


app.use((err, req, res, next) => {
    console.error(err.stack);
    res.redirect('/auth/failure');
});
