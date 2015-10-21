# Feide Connect API Gatekeeper Expressjs Middleware


Usage


	var config = {
		"password": "12334"
	};

	var fc = new FeideConnectAPI(config);
	
	// Use middleware
	app.use('/api', fc.getMiddleware());




