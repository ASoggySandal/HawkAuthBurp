const Http = require('http');
const Hawk = require('hawk');

// Credentials lookup function
const credentialsFunc = function (id) {
    // Your Hawk credentials
    if (id === 'test') {
        return {
            id: 'test',
            key: 'test_key',  // Use your Hawk key here
            algorithm: 'sha256',
            user: 'Steve'  // Arbitrary user info
        };
    }

    return null; // If no credentials are found for the given id
};

// Create HTTP server
const handler = async function (req, res) {
    let payload, status, credentials, artifacts;

    // Authenticate incoming request
    try {
        const authResult = await Hawk.server.authenticate(req, credentialsFunc);
        credentials = authResult.credentials;
        artifacts = authResult.artifacts;

        // Log normalized string and calculated MAC for debugging
        console.log('Server Normalized String:', artifacts);
        console.log('Server MAC:', Hawk.crypto.calculateMac('header', credentials, artifacts));

        payload = `Hello ${credentials.user} ${artifacts.ext || ''}`;
        status = 200;
    } catch (error) {
        console.error('Authentication failed:', error.message);
        payload = 'Shoosh!';
        status = 401;
    }

    // Prepare response headers
    const headers = { 'Content-Type': 'text/plain' };

    // Generate Server-Authorization response header only if authentication passed
    if (status === 200 && credentials && artifacts) {
        const header = Hawk.server.header(credentials, artifacts, {
            payload,
            contentType: headers['Content-Type']
        });
        headers['Server-Authorization'] = header;
    }

    // Send the response back
    res.writeHead(status, headers);
    res.end(payload);
};


// Start the server on 0.0.0.0 and port 8000
Http.createServer(handler).listen(8000, '0.0.0.0', () => {
    console.log('Server running on port 8000');
});
