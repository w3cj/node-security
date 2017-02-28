
#### To view this as a slide deck:

`npm install -g reveal-md`

`npm start`

---

<!-- .slide: data-background="http://i.imgur.com/rbBVg4J.gif" -->

<h1 style="font-family:'MrRobot';color:#CA2222;font-size:6em;">Security</h1>
### with
<img style="display:inline;border:none;height:100px;width:auto;" src="https://raygun.com/blog/wp-content/uploads/2016/05/nodejs-logo.png">
<img style="display:inline;border:none;height:100px;width:auto;" src="https://i.cloudup.com/zfY6lL7eFa-3000x3000.png">


#### hello@cjr.co.de
#### CJ on Denver Devs

---

<!-- https://flixels.s3.amazonaws.com/flixel/de6w5hh1ijhzux3c3pah.webm -->

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/ypy8bw9fgw1zv2b4htp2.webm" data-background-video-loop="loop" data-background-video-muted -->

## Agenda

* whoami
* Why security?
* Security with Node.JS/Express

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/52vy4yxt8yw76d2u8dsm.webm" data-background-video-loop="loop" data-background-video-muted -->

# `whoami`

----

<!-- .slide: data-background="http://galvanize-wp.s3.amazonaws.com/wp-content/uploads/2016/09/14143218/Platte-Oct-2015-4593-min.jpg"  -->

<div style="background: rgba(0, 0, 0, 0.4);border-radius: 50px">
  <h1>CJ</h1>
  <h3>Lead Instructor, Sr. Full Stack Developer</h3>
  <h2>at</h2>
  <img src="http://www.galvanize.com/wp-content/themes/galvanize/img/galvanize-logo.svg" style="height:100px;width:auto;border:none;background:rgba(0, 0, 0, 0)">
</div>

---

<!-- .slide: data-background-video="http://i.imgur.com/mpzh1XB.mp4" data-background-video-loop="loop" data-background-video-muted -->

# Why security?

----

# Show  of hands:
## Who here develops web applications?

----

# Show  of hands:
## Who here is a security engineer?

----

### If you are a web developer you probably don't think of yourself as a security engineer.

>"Our clients don't pay us for security; they want it pretty, they want it feature-complete, and most importantly they want it done yesterday."

[A Gentle Introduction to Application Security](https://paragonie.com/blog/2015/08/gentle-introduction-application-security)

----

# Fact:
### The second your code is deployed in production, your code is the front line of defense for that entire system and quite possibly the entire network.

----

### Logically, that means the software you produce must be made reasonably secure.

----

## Application Security is Every Developer's Responsibility

You _don't_ have to be an expert.

Anything you develop with security in mind will still move the needle in your organization as well as any clients you work with.

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/de6w5hh1ijhzux3c3pah.webm" data-background-video-loop="loop" data-background-video-muted  -->

<div style="background: rgba(0, 0, 0, 0.5);padding: 20px;">

<h3>The topics discussed in this talk are heavily influenced by the [Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet) maintained by [OWASP - Open Web Application Security Project](https://www.owasp.org/index.php/Main_Page) and the [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/) by RisingStack.</h3>
</div>

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/z9wcm9tw5ao9m4w95ysl.webm" data-background-video-loop="loop" data-background-video-muted -->

<div style="background: rgba(0, 0, 0, 0.5);padding: 20px;">
  <h2>Security with Node.JS/Express</h2>
  <ul>
      <li>Mitigate common attacks by setting security related headers</li>
      <li>Protect against brute force authentication attacks</li>
      <li>Manage sessions using cookie best practices</li>
      <li>Mitigate CSRF attacks</li>
      <li>Validate Data to prevent XSS, SQL Injection and Command Injection</li>
      <li>Ensure secure transmission by testing SSL and HSTS</li>
      <li>Check NPM dependencies for known vulnerabilities</li>
  </ul>
</div>

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/3uvqg0wiaxbi5blj9qda.webm" data-background-video-loop="loop" data-background-video-muted -->

## Mitigate common attacks by setting security related headers

----

## Headers

Setting headers from the server is easy and often doesn't require any code changes. Once set, they can restrict modern browsers from running into easily preventable vulnerabilities.

[OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers)

----

## Helmet

[Helmet](https://github.com/helmetjs/helmet) helps you secure your Express apps by setting various HTTP headers. It's not a silver bullet, but it can help!

Helmet is a collection of 10 smaller middleware functions that set HTTP headers:

- [contentSecurityPolicy](https://github.com/helmetjs/csp) for setting Content Security Policy
- [dnsPrefetchControl](https://github.com/helmetjs/dns-prefetch-control) controls browser DNS prefetching
- [frameguard](https://github.com/helmetjs/frameguard) to prevent clickjacking
- [hidePoweredBy](https://github.com/helmetjs/hide-powered-by) to remove the X-Powered-By header
- [hpkp](https://github.com/helmetjs/hpkp) for HTTP Public Key Pinning
- [hsts](https://github.com/helmetjs/hsts) for HTTP Strict Transport Security
- [ieNoOpen](https://github.com/helmetjs/ienoopen) sets X-Download-Options for IE8+
- [noCache](https://github.com/helmetjs/nocache) to disable client-side caching
- [noSniff](https://github.com/helmetjs/dont-sniff-mimetype) to keep clients from sniffing the MIME type
- [xssFilter](https://github.com/helmetjs/x-xss-protection) adds some small XSS protections

----

## Helmet Usage

```sh
npm install -S helmet
```

```js
const express = require('express');  
const helmet = require('helmet');

const app = express();

app.use(helmet());
```

Running `app.use(helmet())` will include 7 of the 10, leaving out `contentSecurityPolicy`, `hpkp`, and `noCache`. You can also use each module individually.

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/rebln7j1jqwq3c8d0fw3.webm" data-background-video-loop="loop" data-background-video-muted -->

## Protect against brute force authentication attacks

----

## Brute Force

In cryptography, a brute-force attack consists of an attacker trying many passwords or passphrases with the hope of eventually guessing correctly. The attacker systematically checks all possible passwords and passphrases until the correct one is found.

[via Wikipedia](https://en.wikipedia.org/wiki/Brute-force_attack)

https://github.com/vanhauser-thc/thc-hydra

----

## Rate Limiting

Limiting the number of requests a user can make can protect your application from brute force attacks.

----

## [express-bouncer](https://github.com/dkrutsko/express-bouncer)

A simple and standalone middleware for express routes which attempts to mitigate brute-force attacks. It works by increasing the delay with each failed request using a Fibonacci formula. Requests are tracking via IP address and can be white-listed or reset on demand.

```js
// Creates a new instance of our bouncer (args optional)
var bouncer = require ("express-bouncer")(500, 900000);

// Add white-listed addresses (optional)
bouncer.whitelist.push ("127.0.0.1");

// In case we want to supply our own error (optional)
bouncer.blocked = function (req, res, next, remaining) {
    res.send (429, "Too many requests have been made, " +
        "please wait " + remaining / 1000 + " seconds");
};

// Route we wish to protect with bouncer middleware
app.post ("/login", bouncer.block, function (req, res) {
    if (LoginFailed) {
        // Login failed
    } else {
        bouncer.reset (req);
        // Login succeeded
    }
});

// Clear all logged addresses
// (Usually never really used)
bouncer.addresses = { };
```

----


## ratelimiter

ratelimiter is an abstract rate limiter for Node.js backed by redis.

`npm install -S ratelimiter`

### Options

 - `id` - the identifier to limit against (typically a user id)
 - `db` - redis connection instance
 - `max` - max requests within `duration` [2500]
 - `duration` - of limit in milliseconds [3600000]

----

## ratelimiter usage

Can be used as a middleware to protect ALL routes.

```js
app.use((req, res, next) => {
  var id = req.user._id;
  var limit = new Limiter({ id: id, db: db });
  limit.get(function(err, limit){
    if (err) return next(err);

    res.set('X-RateLimit-Limit', limit.total);
    res.set('X-RateLimit-Remaining', limit.remaining - 1);
    res.set('X-RateLimit-Reset', limit.reset);

    // all good
    debug('remaining %s/%s %s', limit.remaining - 1, limit.total, id);
    if (limit.remaining) return next();

    // not good
    var delta = (limit.reset * 1000) - Date.now() | 0;
    var after = limit.reset - (Date.now() / 1000) | 0;
    res.set('Retry-After', after);
    res.send(429, 'Rate limit exceeded, retry in ' + ms(delta, { long: true }));
  });
});
```

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/sjytbnalz6tpbgl9jqzn.webm" data-background-video-loop="loop" data-background-video-muted -->

<div style="background: rgba(0, 0, 0, 0.5);padding: 20px;">
  <h2>Manage sessions using cookie best practices</h2>
</div>

----

## Cookie Flags

There are several attributes that can be set on a cookie:
* `secure` - this attribute tells the browser to only send the cookie if the request is being sent over HTTPS.
* `HttpOnly` - this attribute is used to help prevent attacks such as cross-site scripting, since it does not allow the cookie to be accessed via JavaScript.

----

## Cookie Scope

* `domain` - this attribute is used to compare against the domain of the server in which the URL is being requested. If the domain matches or if it is a sub-domain, then the path attribute will be checked next.
* `path` - in addition to the domain, the URL path that the cookie is valid for can be specified. If the domain and path match, then the cookie will be sent in the request.
* `expires` - this attribute is used to set persistent cookies, since the cookie does not expire until the set date is exceeded

----

## cookies in Express

In a newly generated express app, all options are off _by default_

```js
app.use(cookieParser())
```

Set some sensible defaults:

```js
app.use(cookieParser(process.env.COOKIE_SECRET, {
  secure: true,
  httpOnly: true,
  domain: process.env.DOMAIN,
  expires:
}));
```

[cookie-parser on npm](https://www.npmjs.com/package/cookie-parser)

[cookie on npm](https://www.npmjs.com/package/cookie)

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/h1pnkz1q4exz9wy0d70a.webm" data-background-video-loop="loop" data-background-video-muted -->

## Mitigate CSRF attacks

----

## CSRF

Cross-Site Request Forgery is an attack that forces a user to execute unwanted actions on a web application in which they're currently logged in. These attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request.

<a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)">via OWASP</a>

[NodeGoat](https://github.com/OWASP/NodeGoat) - an environment to learn how OWASP Top 10 security risks apply to Node.js

[NodeGoat CSRF demo](https://nodegoat.herokuapp.com/tutorial/a8)

----

## csurf

Node.js CSRF protection middleware.

`npm install -S csurf`

----

## csurf usage

```js
var cookieParser = require('cookie-parser')
var csrf = require('csurf')
var bodyParser = require('body-parser')
var express = require('express')

var app = express()
app.use(cookieParser())

var csrfProtection = csrf({ cookie: true })
var parseForm = bodyParser.urlencoded({ extended: false })

app.get('/form', csrfProtection, function(req, res) {
  // pass the csrfToken to the view
  res.render('send', { csrfToken: req.csrfToken() })
})

app.post('/process', parseForm, csrfProtection, function(req, res) {
  res.send('data is being processed')
})
```

----

## csurf usage

```html
<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">

  Favorite color: <input type="text" name="favoriteColor">
  <button type="submit">Submit</button>
</form>
```

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/n6rqxpk9g9ts0upfbzal.webm" data-background-video-loop="loop" data-background-video-muted -->

## Validate Data to prevent XSS, SQL Injection and Command Injection

----

# Always filter and sanitize user input.

----

## Input comes from _many_ places
* Query parameters
* URL path
* PUT/POST parameters
* Cookies
* Headers
* File uploads
* Emails
* Form fields
* etc.

----

## XSS

There are 2 types of XSS attacks:

### Reflected Cross site scripting

The attacker injects executable JavaScript code into the HTML response with specially crafted links.

```
http://example.com/?user=<script>alert('pwned')</script>
```

### Stored Cross site scripting

The application stores user input which is not correctly filtered. It runs within the user’s browser under the privileges of the web application.

[NodeGoat Stored XSS Demo](https://nodegoat.herokuapp.com/tutorial/a3)

----

## SQL Injection

Injection of a partial or complete SQL query via user input. It can read sensitive information or be destructive as well.

```SQL
select title, author from books where id=$id  
```

`$id` is coming from the user - what if the user enters 2 or 1=1? The query becomes the following:

```SQL
select title, author from books where id=2 or 1=1
```

The easiest way to defend against these kind of attacks is to use parameterized queries or prepared statements.

If you are using PostgreSQL from Node.js then you probably using the node-postgres module. To create a parameterized query:

```js
var q = 'SELECT name FROM books WHERE id = $1';  
client.query(q, ['3'], function(err, result) {});  
```

----

## SQL Injection Testing

http://sqlmap.org/

----

## Command Injection

A technique used by an attacker to run OS commands on the remote web server.

For example:

`https://example.com/downloads?file=user1.txt`

`https://example.com/downloads?file=%3Bcat%20/etc/passwd`

In this example %3B becomes the semicolon, so multiple OS commands can be run.

----

## A few take aways for data validation:

----

#### Always filter and sanitize user input.

----

### Always filter and sanitize user input.

----

## Always filter and sanitize user input.

----

# Always filter and sanitize user input.

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/jjihphnwquisxx0xyxtg.webm" data-background-video-loop="loop" data-background-video-muted -->

## Ensure secure transmission by testing SSL and HSTS

----

## Secure Transmission

### SSL Version, Algorithms, Key length

As HTTP is a clear-text protocol it must be secured via SSL/TLS tunnel, known as HTTPS. Nowadays high grade ciphers are normally used, misconfiguration in the server can be used to force the use of a weak cipher - or at worst no encryption.

You have to test:

* ciphers, keys and renegotiation is properly configured
* certificate validity

----

## Checking for Certificate information

#### [nmap](https://nmap.org/)

```sh
nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995 www.example.com  
```

----

## Testing SSL/TLS vulnerabilities with sslyze

#### [sslyze](https://github.com/iSECPartners/sslyze)

```sh
./sslyze.py --regular example.com:443
```

----

## HSTS

The `Strict-Transport-Security` header enforces secure (HTTP over SSL/TLS) connections to the server. Take the following example from Twitter:

`strict-transport-security:max-age=631138519`

Here the max-age defines the number of seconds that the browser should automatically convert all HTTP requests to HTTPS.

Testing for it is pretty straightforward:

`curl -s -D- https://twitter.com/ | grep -i Strict`

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/bbqzgcm54sbewywlcl1d.webm" data-background-video-loop="loop" data-background-video-muted -->

## Check NPM dependencies for known vulnerabilities

----

> Any dildo can publish something to npm.

-Kyle Coberly

<img src="http://kylecoberly.github.io/images/ketchup-and-mustard-hero.png" style="height:200px;width:auto;border:none;background:rgba(0, 0, 0, 0)">

----

## NPM

With great power comes great responsibility - NPM has lots of packages what you can use instantly, but that comes with a cost: you should check what you are requiring to your applications. They may contain security issues that are critical.

----

## Node Security Platform

Check your npm dependencies for known vulnerabilities.

```sh
npm install -g nsp
nsp check # audit package.json
```

----

## Snyk

Snyk is similar to the Node Security Platform, but its aim is to provide a tool that can not just detect, but fix security related issues in your codebase.

```sh
npm install -g snyk
snyk test # audit node_modules directory
```

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/etkm6cv4mvwc18qejgl3.webm" data-background-video-loop="loop" data-background-video-muted -->


# Review

----

## Mitigate common attacks by setting security related headers

----

## Protect against brute force authentication attacks

----

## Manage sessions using cookie best practices

----

## Mitigate CSRF attacks

----

## Validate Data to prevent XSS, SQL Injection and Command Injection

----

## Ensure secure transmission by testing SSL and HSTS

----

## Check NPM dependencies for known vulnerabilities

---

<!-- .slide: data-background-video="https://flixels.s3.amazonaws.com/flixel/e7n04jknemzalm6lkaev.webm" data-background-video-loop="loop" data-background-video-muted -->

# Final Thoughts

----

## Knowing is half the battle!

----

## Application Security is Every Developer's Responsibility

This doesn't mean you have to be an expert. You can take one step forward on the path towards expertise and stop, and it will still move the needle in your organization as well as any clients you work with.

----

## Security is a mindset, checklist/Top 10 is a place to start, but don't stop there!

---

# Resources

* [reveal-md for slides](https://github.com/webpro/reveal-md)
* [Animations](https://flixel.com/cinemagraphs/fresh/)
* [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)
* [OWASP - Open Web Application Security Project](https://www.owasp.org/index.php/Main_Page)
* [Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet)
* [NodeGoat](https://github.com/OWASP/NodeGoat)
* [Node.js Security Tips](https://blog.risingstack.com/node-js-security-tips/)
* [A Gentle Introduction to Application Security](https://paragonie.com/blog/2015/08/gentle-introduction-application-security)
* [Top Overlooked Security Threats To Node.js Web Applications](http://conferences.oreilly.com/fluent/fluent2014/public/schedule/detail/32664)


---

<!-- .slide: data-background="https://cdn.onelogin.com/images/brands/backgrounds/login/55005df53228a5ce51e06a1c623f36c5fbe2764c.jpg" -->

<div style="background: rgba(0, 0, 0, 0.5);padding: 20px;">


<img src="http://www.galvanize.com/wp-content/themes/galvanize/img/galvanize-logo.svg" style="height:200px;width:auto;border:none;background:rgba(0, 0, 0, 0)">
<h1>is Hiring!</h1>

<a href="http://gjobs.link/ByTeam">gjobs.link/ByTeam</a>

</div>

---

<!-- .slide: data-background="http://i.imgur.com/m2QOD49.gif" -->

<h1 style="font-family:'MrRobot';color:#CA2222;">Thank you!</h1>
<h2 style="font-family:'MrRobot';color:#CA2222;">Security</h2>
##### with
<img style="display:inline;border:none;height:75px;width:auto;" src="https://raygun.com/blog/wp-content/uploads/2016/05/nodejs-logo.png">
<img style="display:inline;border:none;height:75px;width:auto;" src="https://i.cloudup.com/zfY6lL7eFa-3000x3000.png">


#### hello@cjr.co.de
#### CJ on Denver Devs
