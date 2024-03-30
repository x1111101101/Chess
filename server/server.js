const express = require("express")
const session = require('express-session');
const passport = require("passport")
const GoogleStrategy = require('passport-google-oauth20').Strategy 
const fs = require('fs');
const crypto = require('crypto');
const https = require('https')

const app = express()




function initPassport() {
    app.use(passport.initialize());
    app.use(passport.session());
    let json = fs.readFileSync("keys/oauth", 'utf8');
    let oauth = JSON.parse(json)
    // Google OAuth 설정
    passport.use(new GoogleStrategy({
        clientID: oauth.id,
        clientSecret: oauth.key,
        callbackURL: 'https://playchess.kro.kr:8080/auth/google/callback'
    }, (accessToken, refreshToken, profile, done) => {
        // 사용자 정보가 profile에 들어 있습니다.
        return done(null, profile);
    }));

    passport.serializeUser((user, done) => {
        done(null, user);
    });
    
    passport.deserializeUser((user, done) => {
        done(null, user);
    });
}


function init() {
    app.use(session({
        secret: crypto.randomBytes(32).toString('hex'),
        resave: false,
        saveUninitialized: true
    }));
    initPassport()
    const options = {
        key: fs.readFileSync('./keys/private.pem'),
        cert: fs.readFileSync('./keys/public.pem')
    };
    return https.createServer(options, app);
}

const server = init()

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);
app.get("/auth/google/callback", passport.authenticate('google', {
    successRedirect: '/home',
    failureRedirect: '/login'
}))

app.get("/home", (req, res)=> {
    if (req.isAuthenticated()) {
        res.send(`Hello, ${req.user.displayName}!`);
    } else {
        res.send('Hello, guest!');
    }
})

server.listen(8080, ()=>{
    console.log("listening")
})