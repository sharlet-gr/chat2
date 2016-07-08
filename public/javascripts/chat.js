var socket = io();
var sender, receiver;
$(document).ready(function(){
  sender=document.getElementById('sender').innerHTML;
  receiver=document.getElementById('receiver').innerHTML;
  socket.emit('userjoin', sender, receiver);
  $("#logout").click(function(){
    socket.emit('logout');
    window.location.assign('/logout');
  });
});

function submitfunction(){
  var message = $('#m').val();
  if(message != '') {
    $('#messages').append('<li><b style="color:green">Me: </b>' + message + '</li>');
    console.log(sender, receiver);
    socket.emit('chatMessage', sender, message, receiver);
  }
  $('#m').val('');
  return false;
}


socket.on('chatMessage', function(from, message, to){
  if(sender==from)
    $('#messages').append('<li><b style="color:green">Me: </b>' + message + '</li>');
  else
    $('#messages').append('<li><b style="color:#009afd">' + from + '</b>: ' + message + '</li>');
});

socket.on('sessionEnd',function()
{
  alert("This session has expired");
  window.location.assign('/index');
});
 


 


