var mongoose = require('mongoose');
var Message= mongoose.model('Message');
module.exports = function(app){
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
	  {
	    var messages;
	    Message.find({$or: [{from: req.sender, to: req.receiver},{from: req.receiver, to: req.sender}]},function(err, docs){
	      if(err)
	        return next(err);
	      messages=docs;
	      return res.render('chat',{sender: req.sender, receiver: req.receiver, messages: messages});
	    });
	  }
	  else 
	    res.redirect('/logout');
	});

}
