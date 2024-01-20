require('dotenv').config();
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');
const express = require('express');
const crypto = require('crypto');
const { Fido2Lib, coerceToArrayBuffer, coerceToBase64Url } = require("fido2-lib");
const session = require("express-session");
const Redis = require("ioredis");
const RedisStore = require("connect-redis").default;

const port = process.env.PORT || 3000;

const app = express();
const webauthn = express.Router();
const server = http.createServer(app);

const usersPath = __dirname + '/users.json';
const nanoid=(t=21)=>crypto.getRandomValues(new Uint8Array(t)).reduce(((t,e)=>t+=(e&=63)<36?e.toString(36):e<62?(e-26).toString(36).toUpperCase():e>62?"-":"_"),"");
console.log
const fido2 = new Fido2Lib({
  rpId: process.env.RP_ID,
  rpName: process.env.RP_NAME,
  authenticatorUserVerification: 'preferred'
});

function ensureAuthenticated(req, res, next) {
  if (!req.session.loggedIn) {
    res.redirect("/login");
    return;
  }
  next();
}

app.set('trust proxy', 1);
app.set('views', `${process.cwd()}/views`);
app.set('view engine', 'ejs');

const redisClient = new Redis(process.env.REDIS_URL);
const redisStore = new RedisStore({
  client: redisClient,
  prefix: "web_sess:",
});
const sessionParser = session({
  cookie: {
    secure: true,
    maxAge: 1000 * 60 * 60 * 24 * 14
  },
  store: redisStore,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
});
app.use(sessionParser);
app.use(express.json());

app.get("/", ensureAuthenticated, (req, res) => res.render('index'));
app.get("/login", (req, res) => res.render('login', { session: req.session, users: JSON.parse(fs.readFileSync('./users.json')) }));

app.use('/webauthn', webauthn);

app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /'));
app.use('/public', express.static(`${process.cwd()}/public`));

server.listen(port, (err) => {
  if (err) return console.log(err);
  console.log(`[Web] Listening on port ${port}`);
});

webauthn.post('/register', async (req, res) => {
  const username = req.body.username;
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
  if (users[username]) { return res.json({ success: false, error: 'Username already used' }); };

  const options = await fido2.attestationOptions();
  options.user = {
    id: nanoid(10),
    name: username,
    displayName: username
  };

  req.session.userId = options.user.id;
  req.session.username = username;
  req.session.challenge = options.challenge = coerceToBase64Url(options.challenge, "challenge");

  res.json(options);
});

const getAllowCredentials = (user) => user.authenticators.map(auth => ({ type: 'public-key', id: auth.rawId }));

webauthn.post('/login', async (req, res) => {
  const username = req.body.username;
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
  const user = users[username];

  if (!user) { return res.json({ success: false, error: 'User doesn\'t exist' }); };

  const options = await fido2.assertionOptions();
  options.allowCredentials = getAllowCredentials(user);

  req.session.username = username;
  req.session.challenge = options.challenge = coerceToBase64Url(options.challenge, "challenge");

  res.json(options);
});

webauthn.post('/response', async (req, res) => {
  const data = req.body;
  data.rawId = coerceToArrayBuffer(data.rawId, "id");
  for (let thing in data.response) data.response[thing] = coerceToArrayBuffer(data.response[thing], thing);

  const users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
  if (!req.session.username) { return res.json({ success: false, error: 'No username associated with browser' }); };

  if (data.response.attestationObject != null) {
    // register
    const reg = await fido2.attestationResult(data, {
      challenge: data.challenge,
      origin: "https://" + process.env.RP_ID,
      factor: "either"
    });
    if (!reg.authnrData) { return res.json({ success: false, error: 'Unauthorised' }); };
    console.log(reg);

    const user = {
      id: req.session.userId,
      name: req.session.username,
      displayName: req.session.username,
      authenticators: [{
        rawId: coerceToBase64Url(data.rawId, "rawId"),
        publicKey: reg.authnrData.get('credentialPublicKeyPem'),
        counter: reg.authnrData.get('counter'),
        type: 'public-key'
      }],
    };

    users[user.name] = user;
    fs.writeFileSync(usersPath, JSON.stringify(users));

    req.session.loggedIn = true;
    delete req.session.userId;
    delete req.session.challenge;

    return res.json({success: true});
  } else if (data.response.authenticatorData != null) {
    // login
    const user = users[req.session.username];
    const auth = user.authenticators.find(x => x.rawId == coerceToBase64Url(data.rawId, "rawId"));

    const reg = await fido2.assertionResult(data, {
      allowCredentials: getAllowCredentials(user),
      challenge: req.session.challenge,
      origin: "https://" + process.env.RP_ID,
      factor: "either",
      publicKey: auth.publicKey,
      prevCounter: auth.counter,
      userHandle: coerceToArrayBuffer(user.id, "userId"),
    });

    if (!reg.authnrData) { return res.json({ success: false, error: 'Unauthorised' }); };

    auth.counter = reg.authnrData.get('counter');
    users[user.username] = user;
    fs.writeFileSync(usersPath, JSON.stringify(users));
    req.session.loggedIn = true;
    delete req.session.challenge;

    return res.json({success: true});
  }

  res.json({ success: false, error: 'No data on response' });
});

webauthn.post('/logout', (req, res) => {
  req.session.loggedIn = false;
  delete req.session.username;
  res.sendStatus(303);
});