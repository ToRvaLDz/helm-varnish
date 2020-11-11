###############################################################################################
### The perfect Varnish 4.x+ configuration for Joomla, WordPress & other CMS based websites ###
###############################################################################################

######################
#
# UPDATED on July 7th, 2020
#
# Configuration Notes:
# 1. Default dynamic content caching respects your backend's cache-control HTTP header.
#    If however you need to enforce a different cache-control TTL,
#    do a search for "180" and replace with the new value in seconds.
#    Stale cache is served for up to 24 hours.
# 2. Make sure you update the "backend default { ... }" section with the correct IP and port
#
######################

# Varnish Reference:
# See the VCL chapters in the Users Guide at https://www.varnish-cache.org/docs/
# and https://www.varnish-cache.org/trac/wiki/VCLExamples for more examples.

# Marker to tell the VCL compiler that this VCL has been adapted to the new 4.0 format
vcl 4.0;

# Imports
import std;

# Default backend definition. Set this to point to your content server.
backend default {
    .host = "{{ default "google.com" .Values.varnishBackendService }}";
    .port = "{{ default "80" .Values.varnishBackendServicePort }}";
}

acl purge {
        "localhost";
        "10.0.0.0"/8;
}

sub vcl_recv {
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
                return(synth(405,"Not allowed."));
        }
        ban("req.url ~ /");
        return(synth(200, "Ban added"));
    }
  
    # Forward client's IP to the backend
    if (req.restarts == 0) {
        if (req.http.X-Real-IP) {
            set req.http.X-Forwarded-For = req.http.X-Real-IP;
        } else if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        } else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }

    # httpoxy
    unset req.http.proxy;

    # Normalize the query arguments (but exclude for WordPress' backend)
    if (req.url !~ "wp-admin") {
        set req.url = std.querysort(req.url);
    }

    # Non-RFC2616 or CONNECT which is weird.
    if (
        req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE"
    ) {
        return (pipe);
    }

    # We only deal with GET and HEAD by default
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Strip hash, server doesn't need it.
    if (req.url ~ "\#") {
        set req.url = regsub(req.url, "\#.*$", "");
    }

    # Strip a trailing ? if it exists
    #if (req.url ~ "\?$") {
    #    set req.url = regsub(req.url, "\?$", "");
    #}

    # Remove a ";" prefix in the cookie if present
    set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");

    # Are there cookies left with only spaces or that are empty?
    if (req.http.cookie ~ "^\s*$") {
        unset req.http.cookie;
    }

    call mobile_detection;

    # Exclude the following paths (e.g. backend admins, user pages or ad URLs that require tracking)
    # In Joomla specifically, you are advised to create specific entry points (URLs) for users to
    # interact with the site (either common user logins or even commenting), e.g. make a menu item
    # to point to a user login page (e.g. /login), including all related functionality such as
    # password reset, email reminder and so on.
    if(
        req.url ~ "^/admin-AnD"
    ) {
        #set req.http.Cache-Control = "private, max-age=0, no-cache, no-store";
        #set req.http.Expires = "Mon, 01 Jan 2001 00:00:00 GMT";
        #set req.http.Pragma = "no-cache";
        return (pass);
    }

    # Don't cache ajax requests
    if(req.http.X-Requested-With == "XMLHttpRequest" || req.url ~ "nocache") {
        #set req.http.Cache-Control = "private, max-age=0, no-cache, no-store";
        #set req.http.Expires = "Mon, 01 Jan 2001 00:00:00 GMT";
        #set req.http.Pragma = "no-cache";
        return (pass);
    }

    # === STATIC FILES ===
    # Properly handle different encoding types
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf)$") {
            # No point in compressing these
            unset req.http.Accept-Encoding;
        } elseif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } elseif (req.http.Accept-Encoding ~ "deflate") {
            set req.http.Accept-Encoding = "deflate";
        } else {
            # unknown algorithm (aka crappy browser)
            unset req.http.Accept-Encoding;
        }
    }

    # Remove all cookies for static files & deliver directly
    if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|ogg|ogm|opus|otf|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        return (hash);
    }

    return (hash);

}

include "devicedetect.vcl";

sub mobile_detection {
  # Set the default to PC.
  set req.http.X-Varnish-Device = "pc";

  # Test the user agent for mobile devices.
  # @see https://github.com/varnish/varnish-devicedetect

  call devicedetect;
  
  if (req.http.X-UA-Device ~ "^mobile") {
    # Lump all mobile-style devices together.
    set req.http.X-Varnish-Device = "mobile";
  }

  # Test the URL for mobile paths.
  if (req.http.X-Varnish-Device == "mobile" && req.url !~ "^/((secure|donate|blog)/?.*)?$") {
    # If not in the allowed paths, change back to PC.
    set req.http.X-Varnish-Device = "pc";
  }

  # Force to PC when skipMobileDetection cookie is set.
  if (req.http.cookie ~ "skipMobileDetection") {
    set req.http.X-Varnish-Device = "pc";
  }

  # Redirect to mobile site if not already there.
  if (req.http.X-Varnish-Device == "mobile" && req.url !~ "^\/m\/"){
        if ( req.url == "/") {
            return(synth(751, "Moved Temporarily"));
        }else  if(req.url ~ "^(index|dettnews|argnews|news|pagine|catnews|dettgallery).*") {
            return(synth(750, "Moved Temporarily"));
        }
  }

}

sub vcl_backend_response {

    # Don't cache 50x responses
    if (
        beresp.status == 500 ||
        beresp.status == 502 ||
        beresp.status == 503 ||
        beresp.status == 504
    ) {
        return (abandon);
    }

    # === DO NOT CACHE ===
    # Exclude the following paths (e.g. backend admins, user pages or ad URLs that require tracking)
    # In Joomla specifically, you are advised to create specific entry points (URLs) for users to
    # interact with the site (either common user logins or even commenting), e.g. make a menu item
    # to point to a user login page (e.g. /login), including all related functionality such as
    # password reset, email reminder and so on.
    if(
        bereq.url ~ "^/admin-AnD" 
    ) {
        #set beresp.http.Cache-Control = "private, max-age=0, no-cache, no-store";
        #set beresp.http.Expires = "Mon, 01 Jan 2001 00:00:00 GMT";
        #set beresp.http.Pragma = "no-cache";
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Don't cache HTTP authorization/authentication pages and pages with certain headers or cookies
    if (
        bereq.http.Authorization ||
        bereq.http.Authenticate ||
        bereq.http.X-Logged-In == "True" ||
        bereq.http.Cookie ~ "userID" ||
        bereq.http.Cookie ~ "joomla_[a-zA-Z0-9_]+" ||
        bereq.http.Cookie ~ "(wordpress_[a-zA-Z0-9_]+|wp-postpass|comment_author_[a-zA-Z0-9_]+|woocommerce_cart_hash|woocommerce_items_in_cart|wp_woocommerce_session_[a-zA-Z0-9]+)"
    ) {
        #set beresp.http.Cache-Control = "private, max-age=0, no-cache, no-store";
        #set beresp.http.Expires = "Mon, 01 Jan 2001 00:00:00 GMT";
        #set beresp.http.Pragma = "no-cache";
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Don't cache ajax requests
    if(beresp.http.X-Requested-With == "XMLHttpRequest" || bereq.url ~ "nocache") {
        #set beresp.http.Cache-Control = "private, max-age=0, no-cache, no-store";
        #set beresp.http.Expires = "Mon, 01 Jan 2001 00:00:00 GMT";
        #set beresp.http.Pragma = "no-cache";
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Don't cache backend response to posted requests
    if (bereq.method == "POST") {
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Ok, we're cool & ready to cache things
    # so let's clean up some headers and cookies
    # to maximize caching.

    # Check for the custom "X-Logged-In" header to identify if the visitor is a guest,
    # then unset any cookie (including session cookies) provided it's not a POST request.
    if(beresp.http.X-Logged-In == "False" && bereq.method != "POST") {
        unset beresp.http.Set-Cookie;
    }

    # Unset the "pragma" header (suggested)
    unset beresp.http.Pragma;

    # Unset the "vary" header (suggested)
    #unset beresp.http.Vary;

    if (bereq.http.X-UA-Device) {
        if (!beresp.http.Vary) { # no Vary at all
            set beresp.http.Vary = "X-UA-Device";
        } elsif (beresp.http.Vary !~ "X-UA-Device") { # add to existing Vary
            set beresp.http.Vary = beresp.http.Vary + ", X-UA-Device";
        }
    }
    # comment this out if you don't want the client to know your classification
    set beresp.http.X-UA-Device = bereq.http.X-UA-Device;


    # Unset the "etag" header (optional)
    #unset beresp.http.etag;

    # Allow stale content, in case the backend goes down
    set beresp.grace = 24h;

    # Enforce your own cache TTL (optional)
    #set beresp.ttl = 180s;

    # Modify "expires" header - https://www.varnish-cache.org/trac/wiki/VCLExampleSetExpires (optional)
    #set beresp.http.Expires = "" + (now + beresp.ttl);

    # If your backend server does not set the right caching headers for static assets,
    # you can set them below (uncomment first and change 604800 - which 1 week - to whatever you
    # want (in seconds)
    if (bereq.url ~ "\.(ico|jpg|jpeg|gif|png|bmp|webp|tiff|svg|svgz|pdf|mp3|flac|ogg|mid|midi|wav|mp4|webm|mkv|ogv|wmv|eot|otf|woff|ttf|rss|atom|zip|7z|tgz|gz|rar|bz2|tar|exe|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|ods|odp)(\?[a-zA-Z0-9=]+)$") {
        set beresp.http.Cache-Control = "public, max-age=604800";
    }

    if (bereq.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|ogg|ogm|opus|otf|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        unset beresp.http.set-cookie;
        set beresp.do_stream = true;
    }

    # We have content to cache, but it's got no-cache or other Cache-Control values sent
    # So let's reset it to our main caching time (180s as used in this example configuration)
    # The additional parameters specified (stale-while-revalidate & stale-if-error) are used
    # by modern browsers to better control caching. Set these to twice & four times your main
    # cache time respectively.
    # This final setting will normalize cache-control headers for CMSs like Joomla
    # which set max-age=0 even when the CMS' cache is enabled.
    if (beresp.http.Cache-Control !~ "max-age" || beresp.http.Cache-Control ~ "max-age=0") {
        set beresp.http.Cache-Control = "public, max-age=180, stale-while-revalidate=360, stale-if-error=43200";
    }

    # Optionally set a larger TTL for pages with less than 180s of cache TTL
    #if (beresp.ttl < 180s) {
    #    set beresp.http.Cache-Control = "public, max-age=180, stale-while-revalidate=360, stale-if-error=43200";
    #}

    return (deliver);
}

sub vcl_synth {
    if (resp.status == 750) {
        set resp.http.Location = "/m" + req.url;
        set resp.status = 302;
        return(deliver);
    }
    if (resp.status == 751) {
        set resp.http.Location = "/m/index.php";
        set resp.status = 302;
        return(deliver);
    }
}


sub vcl_deliver {
    # Send special headers that indicate the cache status of each web page
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }

    if ((req.http.X-UA-Device) && (resp.http.Vary)) {
        set resp.http.Vary = regsub(resp.http.Vary, "X-UA-Device", "User-Agent");
    }
    return (deliver);

}