var mongoose = require('mongoose');
var user= mongoose.model('user');
module.exports = function(app){
	app.get('/', function(req, res){
		if(!req.user)
		  	return res.render('login');
		res.redirect('/index');
	});

	app.get('/index', function(req, res, next) {
	  if(!req.user)
	    return res.redirect('/');
	  user.find({},{'_id':false,'username':true,'uname':true},function(err,docs){
	    if(err)
	      return next(err);
	    return res.render('index',{user:req.user, userlist:docs});
	  });  
	});
}