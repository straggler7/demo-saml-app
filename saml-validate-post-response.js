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


/////////////////////////////

app.post('/saml/callback', (req, res, next) => {
  passport.authenticate('saml', (err, user, info) => {
      if (err) {
          console.error('Authentication error:', err);
          return res.redirect('/auth/failure');
      }

      if (!user) {
          console.warn('Authentication failed:', info);
          return res.redirect('/auth/failure');
      }

      // Successfully authenticated, establish a session
      req.logIn(user, (loginErr) => {
          if (loginErr) {
              console.error('Login error:', loginErr);
              return res.redirect('/auth/failure');
          }
          return res.redirect('/dashboard');
      });
  })(req, res, next); // Don't forget to pass `req`, `res`, and `next`
});

passport.authenticate('saml', (err, user, info) => {
  if (err) {
      if (err.message.includes('Invalid signature')) {
          console.error('SAML signature validation failed.');
          return res.redirect('/auth/failure?message=invalid-signature');
      }
      console.error('Unexpected error:', err);
      return res.redirect('/auth/failure?message=unexpected-error');
  }

  if (!user) {
      console.warn('Authentication failed:', info);
      return res.redirect(`/auth/failure?message=${encodeURIComponent(info.message || 'Authentication failed')}`);
  }

  req.logIn(user, (loginErr) => {
      if (loginErr) {
          console.error('Session creation failed:', loginErr);
          return res.redirect('/auth/failure?message=login-error');
      }
      return res.redirect('/dashboard');
  });
});

app.use((err, req, res, next) => {
  console.error('Global error handler:', err.stack);
  res.redirect('/auth/failure?message=global-error');
});

passport.use(
  new SamlStrategy(
      {
          // Your SAML strategy config
          failureRedirect: '/auth/failure',
      },
      (profile, done) => {
          // Your user validation logic
      }
  )
);

app.post(
  '/saml/callback',
  passport.authenticate('saml', {
      successRedirect: '/dashboard',
      failureRedirect: '/auth/failure',
  })
);

app.get('/auth/failure', (req, res) => {
  const message = req.query.message || 'Authentication failed. Please try again.';
  res.render('auth-failure', { message });
});
