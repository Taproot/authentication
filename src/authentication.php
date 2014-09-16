<?php
namespace Taproot\Authentication;

use Symfony\Component\HttpFoundation as Http;
use IndieAuth;
use Guzzle;
use DateTime;
use Exception;


/**
 * Client
 *
 * Create a micropub client app — allows users to log in and authorize this app to make requests on their behalf to,
 * e.g. a micropub endpoint, authenticates requests based on remember-me cookie.
 * $dataToCookie and $dataFromCookie map between the array of information about the current user and the string value
 * stored in the remember-me cookie
 *
 * Adds routes:
 * /login (indieauth.login) — POST to this URL with required “me” and optional “next” parameters to start the login process
 * /authorize (indieauth.authorize) — the URL redirected to by the user’s authorization server after successful authorization. Checks details and sets remember-me cookie
 * /logout (indieauth.logout) — POST to this URL (with optional “next” parameter) whilst logged in to log out, i.e. remove the remmeber-me cookies.
 *
 * Adds ->before() handler which attaches data about the current user, which scopes they’ve granted this app (if any)
 * their URL, access token and micropub endpoint to $request. Example usage within a controller:
 *
 *     $token = $request->attributes->get('indieauth.client.token', null);
 *     if ($token !== null) {
 *       // User is logged in as $token['me']
 *       if (!empty($token['access_token'] and !empty($token['micropub_endpoint'])) {
 *         // The user has granted this app privileges detailed in $token['scope'], which can be carried out by sending
 *         // requests to $token['micropub_endpoint'] with $token['access_token']
 *         // Now you might check that the “post” scope is granted, and create some new content on their site (pseudocode):
 *         if (in_array('post', explode($scope, ' '))) {
 *           micrpub_post($token['micropub_endpoint'], $token['access_token'], $postDetails);
 *         }
 *       } else {
 *         // The user has logged in using the basic indieauth flow — we know that they’re authenticated as $token['me'],
 *         // but they haven’t granted us any permissions.
 *       }
 *     }
 *
 * @param \Silex\Application $app
 * @param callable|null $dataToCookie
 * @param callable|null $dataFromCookie
 * @return \Symfony\Component\Routing\RouteCollection
 */
function client($app, $dataToCookie = null, $dataFromCookie = null) {
	$auth = $app['controllers_factory'];

	// If cookie mapping functions aren’t defined, use the simplest approach of encrypting the data.
	if ($dataToCookie === null) {
		$dataToCookie = function ($data) use ($app) {
			return $app['encryption']->encrypt($data);
		};
	}
	if ($dataFromCookie === null) {
		$dataFromCookie = function ($token) use ($app) {
			return $app['encryption']->decrypt($token);
		};
	}

	// If no cookie lifetime is set, default to 60 days.
	$cookieLifetime = !empty($app['indieauth.cookielifetime']) ? $app['indieauth.cookielifetime'] : 60 * 60 * 24 * 60;
	$cookieName = !empty($app['indieauth.cookiename']) ? $app['indieauth.cookiename'] : 'indieauth_token';

	$clientIdForRequest = function  (Http\Request $request) use ($app) {
		// If no explicit client ID is set, use the domain name of this site.
		return !empty($app['indieauth.clientid']) ? $app['indieauth.clientid'] : $request->getHttpHost();
	};

	$redirectUrlForRequest = function (Http\Request $request) use ($app) {
		// If no default login redirect URL is set (it can be reset on a request-by-request basis by setting the “next” parameter), default to the homepage
		$defaultLoginRedirectUrl = !empty($app['indieauth.loginredirecturl']) ? $app['indieauth.loginredirecturl'] : "{$request->getScheme()}://{$request->getHttpHost()}";
		return $request->request->get('next', $defaultLoginRedirectUrl);
	};

	$auth->post('/login/', function (Http\Request $request) use ($app, $cookieName, $redirectUrlForRequest, $clientIdForRequest) {
		$me = $request->request->get('me');

		$next = $redirectUrlForRequest($request);

		if ($me === null) {
			// TODO: better error handling, although in practical cases this will never happen.
			return $app->redirect($next);
		}
		$authorizationEndpoint = IndieAuth\Client::discoverAuthorizationEndpoint(ensureUrlHasHttp($me));
		if ($authorizationEndpoint === false) {
			// If the current user has no authorization endpoint set, they are using the basic indieauth flow.
			$authorizationEndpoint = rtrim($app['indieauth.url'], '/') . '/auth';
			return $app->redirect("{$authorizationEndpoint}?me={$me}&redirect_uri={$next}");
		}
		// As more scopes become defined, this will need to be expanded + probably made configurable.
		$micropubEndpoint = IndieAuth\Client::discoverMicropubEndpoint(ensureUrlHasHttp($me));
		$scope = !empty($micropubEndpoint) ? 'post' : '';
		$random = mt_rand(1000000,pow(2,31));
		$redirectEndpoint = $app['url_generator']->generate('indieauth.authorize', [], true);
		$authorizationUrl = IndieAuth\Client::buildAuthorizationUrl(
			$authorizationEndpoint,
			$me,
			$redirectEndpoint,
			$clientIdForRequest($request),
			$random,
			$scope);
		$response = $app->redirect($authorizationUrl);
		// Retain random state for five minutes in secure, HTTP-only cookie.
		$cookie = new Http\Cookie("{$cookieName}_random", $app['encryption']->encrypt($random), time() + 60 * 5, null, null, true, true);
		$response->headers->setCookie($cookie);
		return $response;
	})->bind('indieauth.login');

	$auth->get('/authorize/', function (Http\Request $request) use ($app, $dataToCookie, $cookieName, $cookieLifetime, $redirectUrlForRequest, $clientIdForRequest) {
		$random = $app['encryption']->decrypt($request->cookies->get("{$cookieName}_random"));
		$me = $request->query->get('me');
		$state = $request->query->get('state');
		$code = $request->query->get('code');
		if ($state != $random) {
			$app['logger']->info('Authentication failed as state didn’t match random in cookie', [
				'state' => $state,
				'cookie.random' => $random
			]);
			return $app->redirect('/');
		}
		$tokenEndpoint = IndieAuth\Client::discoverTokenEndpoint($me);
		$redirectUrl = $app['url_generator']->generate('indieauth.authorize', [], true);
		$token = IndieAuth\Client::getAccessToken($tokenEndpoint, $code, $me, $redirectUrl, $clientIdForRequest($request), $state);
		$token['micropub_endpoint'] = IndieAuth\Client::discoverMicropubEndpoint(ensureUrlHasHttp($me));

		$app['logger']->info("Indieauth: Got token, discovered micropub endpoint", ['token' => $token]);

		$response = $app->redirect($redirectUrlForRequest($request));
		// Store token data in secure, HTTP-only session cookie.
		$tokenCookie = new Http\Cookie($cookieName, $dataToCookie($token), time() + $cookieLifetime, null, null, true, true);
		$response->headers->setCookie($tokenCookie);
		return $response;
	})->bind('indieauth.authorize');

	$auth->post('/logout/', function (Http\Request $request) use ($app, $redirectUrlForRequest, $cookieName) {
		// In the bizarre case that a request to /logout/ also had a basic-flow indieauth token, prevent the ->after() handler
		// from setting remember-me cookies.
		$request->attributes->set('indieauth.islogoutrequest', true);
		$response = $app->redirect($redirectUrlForRequest($request));
		$response->headers->setCookie(new Http\Cookie($cookieName, '', 0));
		return $response;
	})->bind('logout');

	$app->before(function (Http\Request $request) use ($app, $dataFromCookie, $cookieName) {
		// If the user has full indieauth credentials, make their token information (scope,
		// access key, micropub endpoint) available to controllers.
		if ($request->cookies->has($cookieName)) {
			try {
				/**
				 * indieauth.client.token is an array potentially containing the following properties:
				 * * me: URL of the current user (guaranteed to exist + be a valid URL)
				 * * scope: space-separated list of scopes the user has granted this app
				 * * access_token: the user’s access token
				 * * micropub_endpoint: the user’s micropub endpoint
				 *
				 * If only “me” exists then the user is logged in using the basic indieauth flow — their URL is confirmed but they
				 * haven’t granted us any permissions, and maybe don’t even have a micropub endpoint.
				 */
				$token = $dataFromCookie($request->cookies->get($cookieName));
				$loggableToken = $token;
				// Don’t log the sensitive access key, only the length, so devs can see if there *was* an access token or not.
				$loggableToken['access_token'] = 'Unlogged string of length ' . strlen($token['access_token']);
				$request->attributes->set('indieauth.client.token', $token);
				$app['logger']->info('Request has indieauth token', ['token' => $loggableToken]);
			} catch (Exception $e) {
				$app['logger']->warning("Caught an unhandled exception whilst running \$dataFromCookie on the current user’s indieauth token — consider handling this exception appropriately", [
					'exception class' => get_class($e),
					'message' => $e->getMessage()
				]);
			}
		} elseif ($request->query->has('token')) {
			// The user is logging in using the basic indieauth flow, so all we know about them is their URL.
			// A remember-me cookie will be set for them later.
			$client = new Guzzle\Http\Client($app['indieauth.url']);
			try {
				$response = $client->get('session?token=' . $request->query->get('token'))->send();
				$basicToken = json_decode($response->getBody(true), true);
				$request->attributes->set('indieauth.client.token', $basicToken);
			} catch (Guzzle\Common\Exception\GuzzleException $e) {
				$app['logger']->warning('Authenticating user with indieauth.com failed: ' . $e->getMessage());
			}
		}
	});

	$app->after(function (Http\Request $request, Http\Response $response) use ($app, $dataToCookie, $cookieName, $cookieLifetime) {
		// If the request is a basic-flow indieauth login request, set a remember-me cookie.
		if ($request->query->has('token') and $request->attributes->has('indieauth.client.token') and !$request->attributes->get('indieauth.islogoutrequest', false)) {
			$tokenCookie = new Http\Cookie($cookieName, $dataToCookie($request->attributes->get('indieauth.client.token')), time() + $cookieLifetime);
			$response->headers->setCookie($tokenCookie);
		}
	});

	return $auth;
}
/**
 * Token Server
 *
 * Create a micropub server app + token provider — creates token-providing and authorizing endpoints, allows users to
 * authorize other apps to make requests to this one on their behalf, authenticates requests based on access tokens.
 * $dataToToken and $dataFromToken map the access token granted to+used by apps and a user+client id+granted scopes
 *
 * Adds routes:
 * /token — clients POST to this URL with a bunch of details, including encrypted state, to gain an access token.
 *
 * Adds ->before() handler which attaches data about the current user, which app they’re using, what scopes they’re
 * granted on this server to $request.
 *
 * @param \Silex\Application $app
 * @param callable|null $dataToToken
 * @param callable|null $dataFromToken
 * @return \Symfony\Component\Routing\RouteCollection
 */
function server($app, $dataToToken = null, $dataFromToken = null) {
	$auth = $app['controllers_factory'];

	if ($dataToToken === null) {
		$dataToToken = function ($data) use ($app) {
			return $app['encryption']->encrypt($data);
		};
	}

	if ($dataFromToken === null) {
		$dataFromToken = function ($token) use ($app) {
			return $app['encryption']->decrypt($token);
		};
	}

	$auth->post('/token/', function (Http\Request $request) use ($app, $dataToToken) {
		$f = $request->request;
		$me = $f->get('me');
		$code = $f->get('code');
		$clientId = $f->get('client_id');
		$redirectUri = $f->get('redirect_uri');
		$state = $f->get('state');

		// TODO: handle this being false.
		$authorizationEndpoint = IndieAuth\Client::discoverAuthorizationEndpoint(ensureUrlHasHttp($me));
		$auth = IndieAuth\Client::verifyIndieAuthCode(
				$authorizationEndpoint,
				$code,
				$me,
				$redirectUri,
				$clientId,
				$state);

		if (isset($auth['error'])) {
			$app['logger']->warning('Got an error whilst verifying an authorization token', [
					'error' => $auth['error'],
					'description' => $auth['error_description'],
					'authorizationEndpoint' => $authorizationEndpoint
			]);
		}

		$tokenData = [
				'date_issued' => date(DateTime::W3C),
				'me' => $auth['me'],
				'client_id' => $clientId,
				'scope' => isset($auth['scope']) ? $auth['scope'] : '',
				'nonce' => mt_rand(1000000,pow(2,31))
		];

		$token = $dataToToken($tokenData);

		return Http\Response::create(
				http_build_query([
						'me' => $tokenData['me'],
						'scope' => $tokenData['scope'],
						'access_token' => $token
				]),
				200,
				['Content-type' => 'application/x-www-form-urlencoded']);
	})->bind('indieauth.token');

	// TODO: this needs to look in auth headers as well as in the request body
	$app->before(function ($request) use ($app, $dataFromToken) {
		if ($request->request->has('access_token')) {
			$app['logger']->info('Authenticating using access token');
			// The user is authenticating using the full indieauth flow.
			// This request is presumably coming from an app which the user has authorized with some access to this site.
			$tokenStr = $request->request->get('access_token');
			try {
				// $token also contains information e.g. the scopes the current user has.
				// Client app filtering could also be done here.

				$token = $dataFromToken($tokenStr);
				// This token has no particularly sensitive information in so can be logged as-is.
				$app['logger']->info('Access token decrypted to', ['data' => $token]);
				$request->attributes->set('indieauth.server.token', $token);
			} catch (Exception $e) {
				$app['logger']->warning("Caught an unhandled exception whilst executing \$dataFromToken — consider updating your handler to deal with these appropriately.", [
					'exception class' => get_class($e),
					'message' => $e->getMessage()
				]);
			}
		}
	});

	return $auth;
}

// Partially borrowed from https://github.com/tantek/cassis/blob/master/cassis.js — thanks tantek.com!
function ensureUrlHasHttp($wa) {
	if (!$wa ||
			(substr($wa, 0, 7) === 'http://') ||
			(substr($wa, 0, 8) === 'https://') ||
			(substr($wa, 0, 6) === 'irc://')) {
		return $wa;
	}

	if ((substr($wa, 0, 7) === 'Http://') ||
			(substr($wa, 0, 8) === 'Https://')) {
		// handle iOS4 overcapitalization of input entries
		$wa[0] = 'h';
		return $wa;
	}

	return "http://{$wa}";
}