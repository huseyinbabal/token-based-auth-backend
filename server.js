// Required Modules
var express    = require("express");
var morgan     = require("morgan");
var bodyParser = require("body-parser");
var expressJwt = require("express-jwt");
var mongoose   = require("mongoose");
var app        = express();

var port = 3001;
var User     = require('./models/User');

// Connect to DB
mongoose.connect(process.env.MONGO_URL);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(morgan("dev"));



app.post('/authenticate', function(req, res) {

});

app.get('/me', function(req, res) {

});

// Start Server
app.listen(port, function () {
    console.log( "Express server listening on port " + port);
});