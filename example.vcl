vcl 4.1;

import hja;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_recv {
    # JWT Authentication Example
    # Extract JWT token from Authorization header
    if (req.http.Authorization ~ "^Bearer (.+)$") {
        set req.http.token = regsub(req.http.Authorization, "^Bearer (.+)$", "\1");
        
        # Validate the JWT token with your secret
        set req.http.jwt_valid = hja.validate_jwt(req.http.token, "MY_SECRET");
        
        # Reject invalid tokens
        if (req.http.jwt_valid != "true") {
            return (synth(401, "Unauthorized: Invalid JWT token"));
        }
        
        # Clean up headers (optional)
        unset req.http.token;
        unset req.http.jwt_valid;
    } else {
        # No Authorization header or wrong format
        return (synth(401, "Unauthorized: Missing or invalid Authorization header"));
    }
    
    # URL processing example - convert first folder to lowercase
    set req.url = hja.first_folder_lower(req.url);
    
    # Special route for pixel tracking
    if (req.url == "/pixel.gif") {
        return (synth(200, "OK"));
    }
    
    return (hash);
}

sub vcl_synth {
    # Serve a transparent 1px GIF for pixel tracking
    if (req.url == "/pixel.gif") {
        hja.pixel();
        set resp.http.Content-Type = "image/gif";
        set resp.http.Cache-Control = "no-cache, no-store, must-revalidate";
        return (deliver);
    }
}

sub vcl_deliver {
    # Add VMOD info header for debugging (remove in production)
    set resp.http.X-VMOD-Info = hja.info();
    
    # Add JWT validation confirmation header
    set resp.http.X-JWT-Validated = "true";
    
    # Add processed URL info
    set resp.http.X-Processed-URL = req.url;
}

# Example usage:
# 
# Valid JWT request:
# curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EpM5XBzTJZ4J8AfoJEcJrjth8pfH28LWdjLo90sYb9g" http://localhost:6081/API/test
#
# Invalid JWT request:
# curl -H "Authorization: Bearer invalid.token.here" http://localhost:6081/
#
# Pixel tracking request:
# curl http://localhost:6081/pixel.gif
#
# URL processing example (API -> api):
# curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EpM5XBzTJZ4J8AfoJEcJrjth8pfH28LWdjLo90sYb9g" http://localhost:6081/API/users/123 