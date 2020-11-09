require("dotenv").config();

var passport = require("passport");
var Strategy = require("passport-facebook").Strategy;
const session = require("express-session");
const ensureLogin = require("connect-ensure-login");
const cookieParser = require("cookie-parser");
const LowDbStore = require("lowdb-session-store")(session);
const FileSync = require("lowdb/adapters/FileSync");
const adapter = new FileSync("./fiveMA-sessions.db", { defaultValue: [] }); // The default value must be an array.
const lowDb = require("lowdb")(adapter);

const onlyLogged = ensureLogin.ensureLoggedIn();

// Configure the Facebook strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Facebook API on the user's
// behalf, along with the user's profile.  The function must invoke `cb`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
passport.use(
  new Strategy(
    {
      clientID: process.env["FACEBOOK_CLIENT_ID"],
      clientSecret: process.env["FACEBOOK_CLIENT_SECRET"],
      callbackURL: "/return/facebook",
    },
    (accessToken, refreshToken, profile, cb) => {
      // In this example, the user's Facebook profile is supplied as the user
      // record.  In a production-quality application, the Facebook profile should
      // be associated with a user record in the application's database, which
      // allows for account linking and authentication with other identity
      // providers.
      return cb(null, profile);
    }
  )
);

let onSave, onLoad;

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.
passport.serializeUser((user, cb) => {
  console.log("serializeUser", user);

  if (typeof onSave === "function") onSave(user);
  cb(null, user); // Save id only
});

passport.deserializeUser(async (obj, cb) => {
  console.log("deserializeUser", obj);

  let userData = obj;
  if (typeof onLoad === "function") userData = await onLoad(obj);

  cb(null, userData);
});

const init = (app, options) => {
  const bypassURL = options.bypassURL
    ? options.bypassURL
    : ["/login", "/login/facebook", "/return/facebook", "/favicon.ico", "/"];

  const secret = options.secret
    ? options.secret
    : String(Math.floor(Math.random() * Math.exp(32, 2)));

  const expTime = options.expirationTime
    ? options.expirationTime
    : 1000 * 60 * 60 * 24 * 30; // Sessions expire after 30 days

  onSave = options.middleware.onSave;
  onLoad = options.middleware.onLoad;

  app.use(
    session({
      secret,
      resave: true,
      saveUninitialized: true,
      cookie: {
        maxAge: expTime,
      },
      store: new LowDbStore(lowDb, {
        ttl: expTime,
      }),
    })
  );
  app.use(cookieParser());
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(function (req, res, next) {
    // fiveMA bypass rules middleware
    if (!bypassURL.includes(req._parsedOriginalUrl.pathname)) {
      console.log(
        "Bypass list catch: Session failed for URL ",
        req._parsedOriginalUrl.pathname
      );
      return onlyLogged(req, res, next);
    }
    next();
  });

  app.get("/login/facebook", passport.authenticate("facebook"));

  app.get(
    "/return/facebook",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    (req, res) => {
      res.redirect("/");
    }
  );
};

module.exports = init;
