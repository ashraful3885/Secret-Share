require('dotenv').config()
const express = require("express")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const flash = require("connect-flash")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy
const FacebookStrategy = require('passport-facebook').Strategy
const findOrCreate = require('mongoose-findorcreate')
const port = 3000
const app = express()

app.use(bodyParser.urlencoded({extended:true}))
app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(flash())
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://127.0.0.1:27017/usersDB")
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    secrets: [String],
    googleId: String,
    facebookId: String
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema)
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secret"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id, facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
    res.render("home")
});

app.get("/register",function(req,res){
    res.render("register")
});

app.get("/login", function(req,res){
    res.render("login", { message: req.flash("error") })
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secret', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secret',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get("/secrets", function(req,res){
    if(req.isAuthenticated()){
        User.find({secrets: {$ne: null}})
            .then((user)=>{
                res.render("secrets", { userSecret: user })
            })
            .catch(function(err){
                res.render("error")
            })
    } else{
        res.render("unauth")
    }
})

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit")
    } else{
        res.render("unauth")
    }
})

app.get("/logout", function(req,res){
    req.logout(function(err){
        if(err){
            res.render("error")
        } else{
            res.redirect("/")
        }
    })
})

app.post("/register", function(req,res){
    User.register({username:req.body.username}, req.body.password, function(err, user) {
        if(err){
            res.render("error")
        } else{
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets")
            })
        }
    })
})
app.post("/login", function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function(err){
        if(err){
            res.render("error")
        } else{
            passport.authenticate("local", {failureRedirect:"/login", 
            failureFlash:{message: "Wrong username or password"}})
            (req,res, function(){
                res.redirect("/secrets")
            })
        }
    })
})
app.post("/submit", function(req,res){
    const userSecret = req.body.secret
    User.findById(req.user.id)
        .then(function(user){
            user.secrets.push(userSecret)
            user.save()
                .then(function(){
                    res.redirect("/secrets")
                })
                .catch(function(err){
                    res.render("error")
                })
        })
        .catch(function(err){
            res.render("error")
        })
})

app.listen(port, function(){
    console.log("App running on port "+port)
});