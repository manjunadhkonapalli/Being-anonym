//jshint esversion:6

//As early as possible require and configure --> very imp to put it at the very top
//We are not setting a const bcz we just need to require it and then call config 
//on it and we dont need it again it will be active and running
require("dotenv").config();
//After that define our environment variables

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;

//console.log(md5("123abc"));

//Creating an new app instance of express

const app = express();

//using the public directory to store the static files like images, css code
app.use(express.static("public"));
//setting our view engine to use EJS our templating engine
app.set("view engine", "ejs");
//use body parser in order to pass our requests
app.use(bodyParser.urlencoded({extended : true}));

//Setting up the session -- initializing our session with all our options 
app.use(session({
    secret: "I am Working at Microsoft",
    resave: false,
    saveUninitialized: false,
    //cookie: {secure: true} //when  secure is set, and you access your site over HTTP, the cookie will not be set
    cookie: {}  //sometimes removing cookie option might affectthe program
}));

//initialize and start using the passport - for authentication
app.use(passport.initialize());
//Now tell our app to use passport to also set up our session
app.use(passport.session());
//Finally Adding passport-local-mongoose package as a plugin to our mongoose schema just like we did for mongoose encryption package L65-67


mongoose.connect("mongodb+srv://admin-Manjunadh:Test%40123@cluster0.2xzkdui.mongodb.net/userDB", {useNewUrlParser : true});
//mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser : true});


//Simple javaScript object - simple version of schema
// const userSchema = ({
//     email : String,
//     password : String
// });

//This is a proper mongoose schema
const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId: String,
    secret: String
});

//Tap into userschema and add plugin to it(mongoose schema)
//This we are going to use hash and salt our passwords and to save our users into our MongoDB database.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Used to check the .env file required or not
//console.log(process.env.API_KEY);

//Very imp to add this plugin to the schema before we create our mongoose model
//add encrypt package as a plugin to our schema
//This encrypts our entire database including email, password fields, which we dont want for email
//userSchema.plugin(encrypt, {secret : secret});  

//encrypt only certain fields
//userSchema.plugin(encrypt, {secret : process.env.SECRET, encryptedFields : ["password"]});

const User = new mongoose.model("User", userSchema);

//These below 3 lines are to be added right after the above mongoose model 
passport.use(User.createStrategy());

/*Outdated way of se/deserializing --> from passport-local-mongoose--> works for only local strategies
//Serialize means it creates the cookie and stuffs the message namely our users identifications into the cookie
passport.serializeUser(User.serializeUser());  
//Deserialize means it allows passport to be able to crush/open the cookie and discover the message inside it.(to find the user).
passport.deserializeUser(User.deserializeUser());
*/

//Updated way of se/deserializing --> from passport documentation--> using passport to se/deserialize users --> works for all diff strategies not just for the local strategy.
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

//----------------------------------------------------------------------------------------------------------------------
//Configure strategy fo passport google OAuth 2.0
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: absoluteURI + "/auth/google/secrets",
    proxy: true,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //since google+ is sunsetting, the routes willget adjusted through this route.
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    //find or create is not a standard funton in mongoose. So install additional package to make it wotk mongoose-findorcreate.
    User.findOrCreate({ googleId: profile.id, username: profile._json.name }, function (err, user) {
      return cb(err, user);
    });
  }
));
//----------------------------------------------------------------------------------------------------------------------

app.get("/", function(req, res){
    res.render("home");
});

//Inside here we initiate our authentication with google.
app.get("/auth/google", passport.authenticate("google", {scope: ["profile", "email"]})
    //Authenticating the user with google strategy just like we did in app.post("/register") local strategy
    //Here we are saying, use passport to authenticate our user using the google strategy. And scope means, what we want is users profile.
    //SO this below line of code brings up the pop up that allows the user to sign into their gmail account 
);

//after successful authentication, google will redirect to following route
//Here we authenticate them locally and save their login session
app.get("/auth/google/secrets", passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});


app.get("/secrets", function(req, res){
/*
    //Now we no longer need authentication to see the secrets. Because anyone anonymously can see the secrets.
    //But instead we go through our DB at find all the secret that have been submitted on the Database
    if(req.isAuthenticated()){  //The “req. isAuthenticated()” function can be used to protect routes that can be accessed only after a user is logged in eg. dashboard.
        res.render("secrets");
    }else{
        res.redirect("/login");
    }
*/
//This may still have a null value.
//User.find({"secret" : {$exists:true}});
//This will check non null values -->having value for "secret" attribute
User.find({"secret" : {$ne: null}}, function(err, foundUser){
    if(err)
        console.log(err);
    else{
        if(foundUser){
            res.render("secrets", {usersWithSecret: foundUser});
        }
    }
});

});


//after logging in, to submit a secret.
app.get("/submit", function(req, res){

    if(req.isAuthenticated()){  //Before submitting the secret, first check if the
        res.render("submit");
    }else{
        res.redirect("/login");
    }

});

//Updating the secrets and saving them to users DB and showing them on secrets page
app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    //passport catches and saves the users details--when we initiate the new 
    //login session, it will save the users details into request(req) variable.
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err)
            console.log(err);
        else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }

    })
})

//Here we deauthenticate our user and end that user session
app.get("/logout", function(req, res){
    // A predefined function in passport.js documentation - req.logout must need a callback function
    req.logout(function(err){
        if(err)
            console.log(err);
        else
            res.redirect("/");
    });
});

//catches the request from register page through submit button and then posts something onto in
app.post("/register", function(req, res){

/*
//bcrypt --salting and hashing
    bcrypt.hash(req.body.password, saltRounds, function(err, hash){
    //store the hash in password DB
    const newUser = new User({
        email : req.body.username,
        password : hash //Hash generated using bcrypt as well as 10 rounds of salting
    });
    newUser.save(function(err){
        if(err)
            console.log(err);
        else{
            c//we only render this secrets page once the registration is completed
            res.render("secrets");
        }
    });

//Checking if user already exists
    // User.findOne({email : req.body.username}, function(err, foundUser){
        
    //     if(err)
    //         console.log(err);
    //     else
    //     {
    //         if(foundUser)
    //         {
    //             alert("User already exists! Please Login.");
    //             res.render("login");
    //         }
    //     }

    // });

    console.log();

 //If user not exists Create a new user --MD5 hashing
    // const newUser = new User({
    //     email : req.body.username,
    //     password : md5(req.body.password) //turns our password into irreversible hash value
    // });
    // newUser.save(function(err){
    //     if(err)
    //         console.log(err);
    //     else{
    //         //we only render this secrets page once the registration is completed
    //         res.render("secrets");
    //     }
              
    });
*/

//Implementation for passport
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

//catches the request from login page through submit button and then posts something onto in
app.post("/login", function(req, res){

/*
    User.findOne({email : req.body.username}, function(err, foundUser){
        
        if(err)
            console.log(err);
        else
        {
            if(foundUser)
            {
                //Uses bcrypt for salting and hashing
                bcrypt.compare(req.body.password, foundUser.password, function(err, result){
                    if(result === true)
                        res.render("secrets");
                });

                //Uses MD5  for simple hashing
                // if(foundUser.password === md5(req.body.password)){
                //     res.render("secrets");
                // }
            }
        }

    });
*/

const user = new User({
    username: req.body.username,
    password: req.body.password
});

//login funt that passport gives us -- it has to be called on request object 
req.login(user, function(err){
    if(err){
        console.log(err);
    }else{
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        })
    }
})

});

app.listen(process.env.PORT || 3000, function(){
    console.log("Server successfully started on port 3000");
});
