var mongoose = require('mongoose');
var user= mongoose.model('user');
var passport = require('passport');
module.exports = function(app){
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
	    if(err) 
	      console.log(err);
	    req.logIn(User, function(err,success){
	      return res.redirect('/index');   
	    }); 
	  });
	});

	app.post('/login', function(req, res, next) {
	  passport.authenticate('local', function(err,user, info) {
	    if (err) 
	      return next(err);
	    if (!user) {
	      return res.redirect('/');
	    }
	    req.logIn(user, function(err, info) {
	      if (err) 
	        return next(err);
	      return res.redirect('/index');
	    });
	  })(req, res, next);
	});

	app.get('/logout', function(req, res){
	  req.logout();
	  res.redirect('/');
	});
}