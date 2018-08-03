const express = require('express');
var router = express.Router();
var User = require('../models/user');
var bcrypt = require('bcryptjs');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
router.get('/register',function(req,res)
{
    res.render('register');
});
router.get('/login',function(req,res)
{
    res.render('login');
});
router.post('/register',function(req,res)
{
    var name = req.body.name;
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
    var password2 = req.body.password2;
    req.checkBody('name','Name is required').notEmpty();
    req.checkBody('username','username is required').notEmpty();
    req.checkBody('email','email is required').isEmail();
    req.checkBody('email','email is required').notEmpty();
    req.checkBody('password','password is required').notEmpty();
    req.checkBody('password2',"password is required").equals(req.body.password);
    var errors = req.validationErrors()
    {
        if(errors)
        {
           res.render('register',{errors:errors});
        }
        else{
            var newUser = new User({
                name:name,
                password:password,
                email:email,
                password2:password2,
                username:username
            })
            bcrypt.genSalt(10,function(err,salt)
        {
            bcrypt.hash(newUser.password,salt,function(err,hash)
        {
            newUser.password = hash;
            newUser.save();

        })
        req.flash('success_msg','you are created successfully');
        res.redirect('/users/login');
        
        })
            
        }
    }
})
passport.use(new LocalStrategy (function(username,password,done)
{
    var query={username:username}
    User.findOne(query,function(err,user)
{
    if(err) throw err;
    return done(null,user)
})
}))
passport.serializeUser(function(user,done)
{
    done(null,user.id)
});
passport.deserializeUser(function(id,done)
{
    User.findById(id,function(err,user)
{
    done(err,user);
})
})
router.post('/login',passport.authenticate('local'),function(req,res)
{
    res.redirect('/')
})
router.get('/logout', function(req,res)
{
    req.logout();
    req.flash('success_msg','you are logged out successfully');
    res.redirect('/users/login');
})
  module.exports = router;