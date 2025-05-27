sub krn_throttle {
    # called from vcl_recv
    
    # Skip throttling for your internal application
    if (req.http.User-Agent == "-") {
        # Don't throttle internal application
        return;
    }
    
    # Skip throttling for Google bots (business critical)
    if (req.http.User-Agent ~ "(Googlebot|GoogleOther|facebookexternalhit)") {
        # Don't throttle Google - critical for business
        return;
    }

    # Check for suspicious/fake user agents - redirect to captcha
    if (req.http.User-Agent ~ "(Mozilla/5\.0 \(Linux; Android 10; K\)|Mozilla/5\.0 \(Windows NT 6\.1; WOW64\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/30\.0\.1599\.101)") {
        # Check if they have a valid JWT captcha token
        if (req.http.Cookie !~ "captcha_token=([^;]+)") {
            # No captcha token, redirect to captcha
            return (synth(302, "Captcha Required"));
        }
        
        # Extract JWT token from cookie
        set req.http.X-Captcha-Token = regsub(req.http.Cookie, ".*captcha_token=([^;]+).*", "\1");
        
        # Forward to backend for JWT validation (or use inline validation if supported)
        # If validation fails in backend, it should return 401
        set req.http.X-Captcha-Check = "true";
        
        # Still apply rate limiting even with valid captcha
        if (vsthrottle.is_denied(client.ip, 10, 60s)) {
            return (synth(429, "Too Many Requests"));
        }
        return;
    }

    # Other search engine bots - allow reasonable crawling
    if (req.http.User-Agent ~ "(bingbot|YandexBot|Applebot|Screaming|pyhton-request)") {
        if (vsthrottle.is_denied(req.http.User-Agent, 8, 10s)) {
            return (synth(429, "Too Many Requests"));
        }
        set req.http.X-KRN-RateLimit-Remaining = vsthrottle.remaining(req.http.User-Agent, 8, 10s);
    }
    
    # AI/Large language model bots - moderate throttling
    if (req.http.User-Agent ~ "(OAI-SearchBot|ChatGPT-User|ClaudeBot)") {
        if (vsthrottle.is_denied(req.http.User-Agent, 4, 10s)) {
            return (synth(429, "Too Many Requests"));
        }
        set req.http.X-KRN-RateLimit-Remaining = vsthrottle.remaining(req.http.User-Agent, 5, 10s);
    }
    
    # Aggressive or high-volume bots - strict throttling
    if (req.http.User-Agent ~ "(AhrefsBot|Plista|outbrain|Taboolabot|dobot|ViennaTinyBot|trendictionbot|proximic)") {
        if (vsthrottle.is_denied(req.http.User-Agent, 5, 10s)) {
            return (synth(429, "Too Many Requests"));
        }
        set req.http.X-KRN-RateLimit-Remaining = vsthrottle.remaining(req.http.User-Agent, 5, 10s);
    }
    
    # Ad verification services - moderate throttling
    if (req.http.User-Agent ~ "(ias-|TTD-Content)") {
        if (vsthrottle.is_denied(req.http.User-Agent, 4, 10s)) {
            return (synth(429, "Too Many Requests"));
        }
        set req.http.X-KRN-RateLimit-Remaining = vsthrottle.remaining(req.http.User-Agent, 4, 10s);
    }
}

sub vcl_synth {
    # Handle captcha redirect
    if (resp.status == 302 && resp.reason == "Captcha Required") {
        set resp.http.Location = "/captcha.html?return_url=" + req.url;
        set resp.http.Cache-Control = "no-cache, no-store, must-revalidate";
        return (deliver);
    }
    
    # Handle JWT validation failure
    if (resp.status == 401 && resp.reason == "Invalid Captcha Token") {
        set resp.http.Location = "/captcha.html?return_url=" + req.url;
        set resp.http.Set-Cookie = "captcha_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
        return (deliver);
    }
    
    # Handle other synthetic responses
    if (resp.status == 429) {
        set resp.http.Content-Type = "text/plain";
        set resp.http.Retry-After = "10";
        synthetic("Rate limit exceeded. Please try again later.");
        return (deliver);
    }
}

# Alternative approach: Block suspicious user agents entirely
sub krn_block_suspicious {
    # Block obviously fake/malicious user agents
    if (req.http.User-Agent ~ "(Mozilla/5\.0 \(Linux; Android 10; K\)|Mozilla/5\.0 \(Windows NT 6\.1; WOW64\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/30\.0\.1599\.101)") {
        return (synth(403, "Forbidden"));
    }
}