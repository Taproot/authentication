# taproot/authentication

A library for quickly adding full-blown [indieauth](http://indieauth.com)/web sign-in support to Silex/Symfony applications. Built on top of [indieweb/indieauth-client](https://github.com/indieweb/indieauth-client-php).

## Installation

Install using [Composer](https://getcomposer.org):

    ./composer.phar require taproot/authentication:~0.1

## Usage

taproot/authentication exposes two functions, which, given your Silex `$app`, set up pre/post request handlers and return a route collection which you can mount wherever you like.

Both functions require several services on `$app`:

* `url_generator`: a Symfony Routing UrlGeneratorInterface instance, e.g. one provided by a UrlGeneratorServiceProvider in Silex.
* `encryption`: an object implementing two methods, `string encrypt(mixed $data)` and `mixed decrypt(string $token)` capable of encrypting and decrypting arbitrary data. Usually an instance of `[Illuminate\Encryption\Encrypter](https://github.com/illuminate/encryption)`

Both functions will optionally make use of the following services, but do not require them to function:

* `logger`: a [PSR-3](http://www.php-fig.org/psr/psr-3/)-compatible logging interface

### Taproot\Authentication\client()

`client()` implements the logic and routes required for users to log into your app using their domains, and optionally grant it permissions (e.g. to use micropub to post new content to their website).

It returns a RouteCollection ready to be mounted wherever you want, containing the following routes:

* `/login/` (indieauth.login) — POST to this URL with required “me” and optional “next” parameters to start the login process
* `/authorize/` (indieauth.authorize) — the URL redirected to by the user’s authorization server after successful authorization. Checks details and sets remember-me cookie
* `/logout/` (indieauth.logout) — POST to this URL (with optional “next” parameter) whilst logged in to log out, i.e. remove the remmeber-me cookies.

```php
<?php

use Taproot\Authentication;

$app->mount('/', Authentication\client($app));
```

After a successful login, `client()` sets a remember-me cookie on the user’s browser from which they can be identified in future requests. By default the contents of the cookie is just the array containing their information, encrypted, but if you wish to use another form of storage you can pass data -> cookie and cookie -> data functions to `client()`, e.g.:

```php
<?php

use Taproot\Authentication;

$app->mount('/', Authentication\client($app, function (array $data) {
    return storeInDatabase($data);
}, function ($token) {
    return fetchFromDatabase($token);
}));
```

If the pre-request handler finds the remember-me cookie on a request, it turns it into an array of information about the current user and adds it to `$request->attributes` under `indieauth.client.token`.

This array will **always** have a `me` property which is the URL the user signed in as. Additionally, depending on how the user signed in, whether or not they have a micropub endpoint, and what permissions they have granted you, it may have other properties.

This is how you would typically use the token in a controller:

```php
<?php

function ($request) {
    $token = $request->attributes->get('indieauth.client.token', null);
    if ($token !== null) {
      // User is logged in as $token['me']
      if (!empty($token['access_token']) and !empty($token['micropub_endpoint'])) {
        // The user has granted this app privileges detailed in $token['scope'], which can be carried out by sending
        // requests to $token['micropub_endpoint'] with $token['access_token']
        // Now you might check that the “post” scope is granted, and create some new content on their site (pseudocode):
        if (in_array('post', explode($scope, ' '))) {
          micropub_post($token['micropub_endpoint'], $token['access_token'], $postDetails);
        }
      } else {
        // The user has logged in using the basic indieauth flow — we know that they’re authenticated as $token['me'],
        // but they haven’t granted us any permissions.
      }
    }
};
```

`client()` doesn’t require any services other than the ones detailed above, but defaults can be overridden by the following services:

* `indieauth.url`: if a user tries to log in but an authorization server can’t be found, fall back to using this server. Defaults to 'https://indieauth.com'
* `indieauth.cookiename`: the name of the cookie used to remember the current user. _random will be appended to this for the random state persistance. Defaults to 'indieauth_token'.
* `indieauth.cookielifetime`: the lifetime, in seconds, for indieauth remember-me cookies to last. Defaults to 60 days.
* `indieauth.loginredirecturl`: if no “next” POST parameter is given on login attempts, redirect to this URL. If unset, redirects to `$request->getHttpHost()`
* `indieauth.clientid`: the string to use to identify this indieauth app. If unset, defaults to `$request->getHttpHost()`
* `indieauth.securecookie`: bool, whether or not to set the auth process and token cookies to HTTPS-only. Defaults to true, turn off only for development.

### Taproot\Authentication\server()

`server()` creates event handlers and routes implementing a ticket provider and resource server (i.e. [micropub](http://indiewebcamp.com/micropub) endpoint which client apps can make posts to on behalf of users).

It returns a RouteCollection ready to be mounted wherever you want, with the following route:

* `/token/` (indieauth.token) — clients POST to this URL with a bunch of details, including encrypted state, to gain an access token.

```php
<?php

use Taproot\Authentication;

$app->mount('/', Authentication\server($app);
```

During the authorization process, the server creates an access token for the client app, granting them certain permissions (scope). Then, when client apps make requests with the access token,  a pre-request listener picks them up and annotates the `$request` object with information about the user and client “logged in”.

Here’s how it would typically be used in a controller — for example, a micropub endpoint:

```php
<?php

function ($request) {
    $token = $request->attributes->get('indieauth.server.token', null);
    if ($token !== null) {
        // The request is authenticated, made by $token['client_id'] on behalf of $token['me'] (guaranteed to be a valid URL).
        // $token['date_issued'] is a string containing the ISO8601-formatted datetime the token was issued on.
        if (in_array('post', explode($token['scope'], ' '))) {
            // The user granted this app the “post” permission, so we can go ahead and take other data in $request and make a new post.
            newPost($request->request->all());
        }
    }
};

```

Much like `client()`, by default `server()` maps between access tokens and their data without saving them to persistant storage — the access token is simply an encrypted form of the array, which is then decrypted. This is very simple, but there are advantages to storing access token data persistently — for example, listing authorized apps and allowign them to be revoked.

You may define your own token -> data and data -> token functions in exactly the same way as with `client()`:

```php
<?php

use Taproot\Authentication;

$app->mount('/', Authentication\server($app, function (array $data) {
    return saveData($data);
}, function ($token) {
    return fetchDataForToken($token);
}));
```

## Questions with answers

### Can an app be both a client and a server?

Yes it can! In fact before this code was separated into client and server code when it was packaged up, the two shared the same route collection and before/after listeners. Simply mount + set up both route collections.

### Can this be used outside of Silex?

It works best with silex but with some small modifications might be easily adapted to any project using Symfony HTTP Kernel — if you’re interested in getting this working, raise an issue.

Alternatively, take a look at [indieweb/indieauth-client](https://github.com/indieweb/indieauth-client-php), [Aaron Parecki](https://aaronparecki.com)’s excellent library of which taproot/authentication is merely a thin wrapper.

## Contributions + Testing

Contributions (especially bug reports and security reviews) are greatly welcome! Please raise an issue here, or ping barnabywalters on the [indiewebcamp IRC channel](http://indiewebcamp.com/IRC).

As of version 0.1.0, there’s only the stub of a test suite — I plan to write comprehensive functional tests using a mock app, but such things take time, and the code is already in daily use on waterpigs.co.uk.

## Changelog

### v0.1.0 2014-04-09

* Initial extraction from Taproot
* Split messy code into well-defined client app and resource server portions
* Initial documentation
* Stubbed test suite
