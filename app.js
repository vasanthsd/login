var express = require('express');
var path = require('path');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var exphbs = require('express-handlebars');
var session = require('express-session');
var expressValidator = require('express-validator');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var flash = require('connect-flash');
var mongodb = require('mongodb');
var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/loginauth');
var db = mongoose.connection;

//routes
var routes = require('./routes/index');
var users = require('./routes/users');

//init app
var app = express();

//view -engine
app.set('views', path.join(__dirname, 'views'));
app.engine('handlebars', exphbs({defaultLayout:'layout'}));
app.set('view engine', 'handlebars');
//body parser
app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());
app.use(cookieParser());
//set static
app.use(express.static(path.join(__dirname,'public')));
//session
app.use(session({
    secret:'secret',
    saveUninitialized:true,
    resave:true
}));
//passport 
app.use(passport.initialize());
app.use(passport.session());
//express validator
app.use(expressValidator({
    errorFormatter: function(param, msg, value) {
        var namespace = param.split('.')
        , root    = namespace.shift()
        , formParam = root;
  
      while(namespace.length) {
        formParam += '[' + namespace.shift() + ']';
      }
      return {
        param : formParam,
        msg   : msg,
        value : value
      };
    }
  }));
  //flash 
  app.use(flash());
  //global vars
  app.use(function(req,res,next)
{
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    res.locals.user = req.user ||null;
    next();
})

app.use('/',routes);
app.use('/users',users);
app.set('port', (process.env.PORT || 3000));

app.listen(app.get('port'), function(){
	console.log('Server started on port '+app.get('port'));
});