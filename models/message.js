var mongoose=require('mongoose');

var messageSchema = new mongoose.Schema({
	content:{type: String, required: true},
	from:{type: String, required:true},
	to:{type: String, required: true},
	time:{type:Date,default:Date.now}
});

mongoose.model('Message', messageSchema);

