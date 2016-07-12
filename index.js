var express=require('express');
var app = express();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var passport = require('passport');
var bCrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');

var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/shw');
require('./models/user');
require('./models/message');

require('./config/passport')(passport);

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

require('./controllers/index.js')(app);
require('./controllers/user.js')(app);
require('./controllers/chat.js')(app);

var sockets=[];
require('./sockets/beginchat.js')(io,sockets);

// Listen application request on port 3000
http.listen(3000, function(){
  console.log('listening on *:3000');
});
