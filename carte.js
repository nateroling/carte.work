#!/usr/bin/node
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const cors = require('cors');
const errorHandler = require('errorhandler');
const passport = require('passport');
const config = require('./config');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy
const pouchdb = require('pouchdb');


const authenticationStrategy = new OIDCStrategy(config.credentials,
 function(req, iss, sub, profile, accessToken, refreshToken, done) {
    console.log(profile);
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    return done(null, profile.oid);
  }
);


//Configure isProduction variable
const isProduction = process.env.NODE_ENV === 'production';

const allowUrl = ['/', '', '/login/', '/login', '/auth'];
const authenticationMiddleware = (whiteList =[]) => (req, res, next) => {
    if (whiteList.find(u => u === req.path)) return next();
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

//Initiate our app
const app = express();

//Configure our app
app.use(cors());
app.use(require('morgan')('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: 'passport-tutorial', cookie: { maxAge: 60000 }, resave: false, saveUninitialized: false }));

if(!isProduction) {
  app.use(errorHandler());
}
app.use(passport.initialize());
app.use(passport.session());
app.use(authenticationMiddleware(allowUrl));
passport.use(authenticationStrategy);

app.use('/db', require('pouchdb-express-router')(pouchdb));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});


app.get('/',  function(req, res){
    if (req.isAuthenticated()) {
       res.send("Welcome to the secrets.");
    } else {
       res.send("You are not invited.");
    }
});

app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/fail' }),
  function(req, res){
   res.send("Welcome to the secrets.");
});

app.get('/fail', function(req, res) {
  res.send("NOT AUTHORIZED");
})

app.post('/auth',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/fail' }),
  function(req, res) { 
    res.redirect('/');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(8080, () => console.log('Server running on http://localhost:8080/'));
