
var basicAuthParser = require('basic-auth-parser');

var FeideConnectAPIRequest = function(feideconnect, req, opts) {
	this.feideconnect = feideconnect;
	this.req = req;
	this.opts = opts;

	this.userid = null;
	this.useridsec = null;

	this.clientid = null;
	this.scopes = null;

	this.inited = false;
};

FeideConnectAPIRequest.prototype.init = function() {
	this.authenticatePlatform();
	this.parseHeaders();
	this.inited = true;
}

FeideConnectAPIRequest.prototype.parseHeaders = function() {

	if (this.req.headers['x-feideconnect-userid']) {
		this.userid = this.req.headers['x-feideconnect-userid'];
	}
	if (this.req.headers['x-feideconnect-userid-sec']) {
		this.useridsec = this.req.headers['x-feideconnect-userid-sec'].split(',');
	}
	if (this.req.headers['x-feideconnect-scopes']) {
		this.scopes = this.req.headers['x-feideconnect-scopes'].split(',');
	}
	if (this.req.headers['x-feideconnect-clientid']) {
		this.clientid = this.req.headers['x-feideconnect-clientid'];
	}
	// console.log(this);
	// console.log("Headers", JSON.stringify(this.req.headers, undefined, 3));

};


FeideConnectAPIRequest.prototype.hasUser = function() {
	return this.userid !== null;
}
FeideConnectAPIRequest.prototype.requireUser = function() {
	if (!this.hasUser()) {
		throw new Error("Request is required to be on behalf of an authenticated end user but is not.")
	}
}
FeideConnectAPIRequest.prototype.requireUserUnlessScopes = function(scopes) {
	if (!this.hasScopes(scopes)) {
		throw new Error("Request is required to be on behalf of an authenticated end user but is not. " + 
			"This requirement is relaxed when request is authorized with the sufficient scopes");
	}
}



FeideConnectAPIRequest.prototype.hasScope = function(scope) {
	if (this.scopes === null) { return false; }
	for (var i = 0; i < this.scopes.length; i++) {
		if (this.scopes[i] === scope) {
			return true;
		}
	};
	return false;
}

FeideConnectAPIRequest.prototype.hasScopes = function(scopes) {
	for (var i = 0; i < scopes.length; i++) {
		if (!this.hasScope(scopes[i])) {
			return false;
		}
	}
	return true;
}

FeideConnectAPIRequest.prototype.requireScopes = function(scopes) {
	if (!this.hasScopes(scopes)) {
		throw new Error("Request is not authorized with all the required sub scopes");
	}
}


FeideConnectAPIRequest.prototype.authenticatePlatform = function() {

	var authHeader = this.req.get('Authorization');
	if (!authHeader) {
		throw new Error("Missing Authorization header");
	}

	var authParts = basicAuthParser(authHeader);
	var authOK = (authParts.scheme === 'Basic' && authParts.username === 'feideconnect' && 
		authParts.password === this.feideconnect.config.password);

	if (!authOK) {
		throw new Error("Request was not propertly authenticated from the Connect platform.")
	}


	// console.log("Parts", JSON.stringify(authParts, undefined, 2));
}




var FeideConnectAPI = function(config) {
	this.config = config;
};

FeideConnectAPI.prototype.cors = function() {
	return function(req, res, next) {
		res.header("Access-Control-Allow-Origin", "*");
		res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
		console.log("Method is ", req.method);
		if (req.method === 'OPTIONS') {
			return res.sendStatus(204);
		}
		next();
	}
}

FeideConnectAPI.prototype.setup = function(opts) {
	var feideconnectapi = this;
	return function(req, res, next) {
		req.feideconnect = new FeideConnectAPIRequest(feideconnectapi, req, opts);
		try {
			req.feideconnect.init();	
		} catch (err) {
			return res.status(500).json({"message": err.message});
		}
		
		next();
	};
}

FeideConnectAPI.prototype.policy = function(policy) {
	var that = this;
	return function(req, res, next) {
		
		if (!req.feideconnect) {
			throw new Error("FeideConnect needs to be setup before we can run a policy. Use the setup() middleware first.")
		}

		for(var key in policy) {

			if (policy[key] !== false) {

				switch(key) {
					case "requireUser": 
						req.feideconnect.requireUser();
						break;

					case "requireUserUnlessScopes": 
						req.feideconnect.requireUserUnlessScopes(policy[key]);
						break;			

					case "requireScopes": 
						req.feideconnect.requireScopes(policy[key]);
						break;

					default:
						throw new Error("Cannot process unknown policy [" + key +"]");

				}
			}

		}
		
		next();
	};
}




exports.FeideConnectAPI = FeideConnectAPI;
