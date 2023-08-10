const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session')
const customer_routes = require('./router/auth_users.js').authenticated;
const genl_routes = require('./router/general.js').general;

const app = express();

app.use(express.json());

app.use("/customer",session({secret:"fingerprint_customer",resave: true, saveUninitialized: true}))

app.use("/customer/auth/*", function auth(req, res, next) {
    // Check if there's an authorization object within the session
    if (req.session && req.session.authorization) {
        // Extract the access token from the session
        const token = req.session.authorization.accessToken;
        
        // Verify the token
        jwt.verify(token, "access", (err, decodedData) => {
            // If there's no error and the token data is present
            if (!err && decodedData) {
                // Store the decoded data into the request for subsequent middleware/route handlers
                req.user = decodedData;
                next();  // proceed to the next middleware or route handler
            } else {
                // If there's an error during token verification
                return res.status(403).json({ message: "User not authenticated" });
            }
        });
    } else {
        // If there's no authorization object in the session
        return res.status(403).json({ message: "User not logged in" });
    }
});

 
 
const PORT =5000;

app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.listen(PORT,()=>console.log("Server is running"));