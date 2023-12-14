require("dotenv").config()
const express=require("express")
const bodyparser=require("body-parser")
const mongoose=require("mongoose")

const session=require("express-session")
const passport=require("passport")
const passlocalmon=require("passport-local-mongoose")

const findOrCreate=require("mongoose-findorcreate")
const FacebookStrategy=require("passport-facebook").Strategy                ////For Facebook
const GoogleStrategy = require("passport-google-oauth20").Strategy;         ////For Google



////////////MiddleWares////////////////
const app=express()
app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyparser.urlencoded({extended:true}))

app.use(session({
    secret: 'hackerorWot',
    resave: false,
    saveUninitialized: true
  }))
  
app.use(passport.initialize())
app.use(passport.session())


////////////Database/////////////////
mongoose.connect("mongodb://127.0.0.1:27017/PracOfAuthSec");

const userschema = new mongoose.Schema({
  email: String,
  displayName: String,
  password: String,
  facebookId: String,
  googleId: String,               
  secret:String                   
});

userschema.plugin(passlocalmon);
userschema.plugin(findOrCreate);

const User=new mongoose.model("User",userschema)

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


/////////////////////// For Facebook ///////////////////////////
  passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/callback",
    profileFields: ['id', 'displayName', 'photos', 'email']
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ email:profile.emails[0].value,displayName:profile.displayName,facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

///////////////Google
passport.use(new GoogleStrategy({
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { username: profile.emails[0].value, googleId: profile.id },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);


/////////////////////Routes/////////////////////
//Main Route
app.route('/').get(function(req,res){
    res.render("home")

})


//Facebook 
app.get('/auth/facebook',
  passport.authenticate('facebook',{scope: [ "email" ]}));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });


//Google 
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile","email"] })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);                                                                            //Google & Facebook That's It....................




//Login Route
app.route('/login').get(function(req,res){
    res.render("login")

}).post(function(req,res){
    const user1=new User({
      email:req.body.username,
      password:req.body.password
    })

    req.login(user1, function(err) {
      if (err) { 
          console.log(err); 
      }else{
          passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets")
            })
        }
      })
  })


//Register Route
app.route('/register').get(function(req,res){
    res.render("register")

})
.post(function(req,res){
    User.register({username:req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect('/register')
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            })

        }
      })
    })


//Secrets Route
app.route("/secrets").get(function (req, res) {
  User.find({ secret: { $ne: null } })
    .then((data) => res.render("secrets", { userwithsecret: data }))
    .catch((err) => console.log(err));

});



//Logout Routes
app.route("/logout").get(function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }
        res.redirect('/')
    })
   
})



//Submit Route
app.route('/submit').get((req,res)=>{
  req.isAuthenticated() ? res.render('submit') : res.redirect('/login')
}).post((req,res)=>{

  // console.log(req.user);
  const submitedsecret = req.body.secret
  console.log(req.user.id);

  User.findById(req.user.id)
  .then((data)=>{
    console.log(data)
    data.secret=submitedsecret
    data.save().then(() => res.redirect("/secrets"))
  })
  .catch((err)=>console.log(err))
})



app.listen(3000,function(){
    console.log("Server Run's On 3000 Port");
})






//Google ID & Secret:-----
//Client Id     :84976460219-jqvo2pfbhid622te4jt2t71orch3oece.apps.googleusercontent.com
//Client Secret : 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


//Facebook ID & Secret:----
// FACEBOOK_APP_ID = 556492972910338;
// FACEBOOK_APP_SECRET = e350af0706d4fd15ffadbbd997631c34;
