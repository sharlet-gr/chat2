var express=require('express');
var app = express();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var passport = require('passport');
var session = require('express-session');
var bCrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var mongoose=require("mongoose");
var LocalStrategy = require('passport-local').Strategy;

mongoose.connect('mongodb://localhost/shw');
require('./models/user');
var user= mongoose.model('user');

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.static(path.join(__dirname, 'public')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({ secret: 'shsh' }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(function(username, password, done) {
  user.findOne({ username: username }, function(err, user, error) {
    if (err) return done(err);
    if (!user){
      return done(null, false, { messages: 'Incorrect username.' });
    }
    user.comparePassword(password, function(err, isMatch, error) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { messages: 'Incorrect password.' });
      }
    });
  });
}));
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  user.findById(id, function(err, user) {
    done(err, user);
  });
});

app.get('/', function(req, res){
  if(!req.user)
   return res.render('login');
  res.redirect('/index');
});

app.get('/index', function(req, res, next) {
  if(!req.user)
    return res.redirect('/');
  user.find(function(err,docs){
    if(err)
      return next(err);
    return res.render('index',{user:req.user, userlist:docs});
  });  
});

app.get('/register', function(req, res, next) {
  if(!req.user)
    return res.render('register');
  res.redirect('/index');  
});

app.post('/register', function(req, res) {
  var User= new user();
  User.uname=req.body.uname;
  User.username=req.body.username; 
  User.password=req.body.password;
  User.save(function(err){
    if(err) console.log(err);
    req.logIn(User, function(err,success){
      return res.redirect('/index');   
    }); 
  });
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err,user, info) {
    if (err) return next(err);
    if (!user) {
      return res.redirect('/');
    }
    req.logIn(user, function(err, info) {
      if (err) return next(err);
      return res.redirect('/index');
    });
  })(req, res, next);
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.param('sender',function(req,res,next,sender){
  req.sender=sender;
  return next();
});
app.param('receiver',function(req,res,next,receiver){
  req.receiver=receiver;
  return next();
});

app.get('/from/:sender/to/:receiver',function(req,res,next){
  if(!req.user)
    return res.redirect('/');
  if(req.sender == req.receiver)
    return res.redirect('/index');
  if(req.user.username == req.sender)
    return res.render('chat',{sender: req.sender, receiver: req.receiver});
  res.redirect('/logout');
});

var sockets=[];
io.on('connection', function(socket){
  socket.on('userjoin',function(sender, receiver){
    sockets.push({id:socket.id, sender:sender, receiver:receiver});
  });
  socket.on('chatMessage',function(sender, message, receiver){
    for (var i = 0; i < sockets.length; i++) {
      if((sockets[i].sender==sender && sockets[i].receiver==receiver)||(sockets[i].sender==receiver && sockets[i].receiver==sender))
        socket.broadcast.to(sockets[i].id).emit( 'chatMessage', sender, message, receiver);
    }
  });
  socket.on('disconnect',function(){
    console.log("disconnect",socket.id);
    var sender, receiver;
    for (var i = 0; i < sockets.length; i++) {
      if(sockets[i].id == socket.id)
      {
        sender=sockets[i].sender;
        receiver=sockets[i].receiver;
        sockets.splice(i,1);
        break;
      }
    }
  });
  socket.on('logout',function(){
    var sender, receiver;
    for (var i = 0; i < sockets.length; i++) {
      if(sockets[i].id == socket.id)
      {
        sender=sockets[i].sender;
        receiver=sockets[i].receiver;
        // sockets.splice(i,1);
        break;
      }
    }
    for (var i = 0; i < sockets.length; i++){
      if(sockets[i].sender==sender)
      {
        socket.broadcast.to(sockets[i].id).emit('sessionEnd');
        sockets.splice(i,1);
      }
    }
  });
});
// Listen application request on port 3000
http.listen(3000, function(){
  console.log('listening on *:3000');
});
