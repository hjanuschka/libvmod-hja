============
vmod-hja
============

SYNOPSIS
========

import hja;

DESCRIPTION
===========

Hja Varnish vmod providing JWT (JSON Web Token) validation functionality without external dependencies.

This vmod implements JWT validation using HMAC-SHA256 signature verification and expiration checking,
making it suitable for authentication and authorization in Varnish Cache configurations.

FUNCTIONS
=========

validate_jwt
------------

Prototype
        ::

                validate_jwt(STRING token, STRING secret)
Return value
	STRING
Description
	Validates a JWT token using the provided secret. Returns "true" if the JWT
	is valid and not expired, "false" otherwise. Uses HMAC-SHA256 for signature
	verification.

	The function performs the following validations:
	- Verifies the JWT has the correct structure (header.payload.signature)
	- Checks that the header specifies HS256 algorithm
	- Validates the HMAC-SHA256 signature using the provided secret
	- Checks token expiration if an "exp" claim is present

Example
        ::

                set req.http.jwt_valid = hja.validate_jwt(req.http.token, "MY_SECRET");

first_folder_lower
------------------

Prototype
        ::

                first_folder_lower(STRING path)
Return value
	STRING
Description
	Converts the first folder in a URL path to lowercase
Example
        ::

                set req.url = hja.first_folder_lower(req.url);

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the ``varnishtest`` tool.

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

Usage::

 ./autogen.sh
 ./configure

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called
with ``--prefix=$PREFIX``, use

::

 export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
 export ACLOCAL_PATH=${PREFIX}/share/aclocal

The module will inherit its prefix from Varnish, unless you specify a
different ``--prefix`` when running the ``configure`` script for this
module.

Make targets:

* make - builds the vmod.
* make install - installs your vmod.
* make check - runs the unit tests in ``src/tests/*.vtc``.
* make distcheck - run check and prepare a tarball of the vmod.

If you build a dist tarball, you don't need any of the autotools or
pkg-config. You can build the module simply by running::

 ./configure
 make

Installation directories
------------------------

By default, the vmod ``configure`` script installs the built vmod in the
directory relevant to the prefix. The vmod installation directory can be
overridden by passing the ``vmoddir`` variable to ``make install``.

USAGE
=====

JWT Validation
--------------

In your VCL you can use JWT validation along the following lines::

        import hja;

        sub vcl_recv {
                # Validate JWT token from Authorization header
                if (req.http.Authorization ~ "^Bearer (.+)$") {
                        set req.http.token = regsub(req.http.Authorization, "^Bearer (.+)$", "\1");
                        set req.http.jwt_valid = hja.validate_jwt(req.http.token, "MY_SECRET");
                        
                        if (req.http.jwt_valid != "true") {
                                return (synth(401, "Unauthorized"));
                        }
                }
        }

Path Processing
---------------

For URL path processing::

        import hja;

        sub vcl_recv {
                # Convert first folder to lowercase
                set req.url = hja.first_folder_lower(req.url);
        }

COMMON PROBLEMS
===============

* configure: error: Need varnish.m4 -- see README.rst

  Check whether ``PKG_CONFIG_PATH`` and ``ACLOCAL_PATH`` were set correctly
  before calling ``autogen.sh`` and ``configure``

* Incompatibilities with different Varnish Cache versions

  Make sure you build this vmod against its correspondent Varnish Cache version.
  For instance, to build against Varnish Cache 4.1, this vmod must be built from
  branch 4.1.

SECURITY NOTES
==============

* Keep your JWT secrets secure and use strong, randomly generated keys
* The JWT validation only supports HS256 (HMAC-SHA256) algorithm
* Tokens without expiration claims will not be rejected based on time
* This implementation does not support JWT key rotation
