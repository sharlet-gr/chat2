var LocalStrategy = require('passport-local').Strategy;
var mongoose=require("mongoose");
var user= mongoose.model('user');
module.exports = function(passport){
	passport.serializeUser(function(user, done) {
	  done(null, user.id);
	});
	passport.deserializeUser(function(id, done) {
	  user.findById(id, function(err, user) {
	    done(err, user);
	  });
	});
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
};
