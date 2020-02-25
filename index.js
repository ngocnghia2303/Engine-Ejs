var express = require('express');
var app = express();
const port = process.env.PORT || 3000

//Engine Ejs
app.set('view engine', 'ejs');
app.set('views', './views');
//midleware Static
app.use(express.static('public'))

//body-parser
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: false }));

//Mongoose with password authentication 
var mongoose = require('mongoose'),
    bcrypt = require('bcrypt');

var User = require('./Models/user-model');

//connect database
mongoose.connect('mongodb+srv://ngocnghia:nghiadeptrai@khoa-pham2020-buqro.gcp.mongodb.net/ChatApp-LindaHTV?retryWrites=true&w=majority', { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true }, function (err) {
    if (err) {
        console.log("Linda Connect Mongo have erros: " + err);
    } else {
        console.log("Linda's Mongo Server Connected Successfully ");
    };
});

mongoose.set('useFindAndModify', false);

//MONGO ERRO: E11000 duplicate key error collection

//use:=====> uuidv4
// var uuidv4 = require('uuid/v4');
// app.use(session({
//   genid: function(req) {
//   	return uuidv4() 
//   }
// }));

//use:======> session
var session = require('express-session');
var MongoDBStore = require('connect-mongodb-session')(session);


var jwt = require('jsonwebtoken');
var secret = ">SDsdungchoaibiet***";

//GET & POST PAGES

app.get('/', function (req, res) {
    res.render('home.ejs', { page: 'choice' })
})

//Sign In Create a new user
app.get('/sign', function (req, res) {
    res.render('home.ejs', { page: 'signin' })
})

app.post('/sign', function (req, res) {
    var status = false;
    if (req.body.alone) {
        status = true;
    };
    var creatuser = new User({
        username: req.body.email,
        password: req.body.pwd,
        name: req.body.name,
        location: req.body.address,
        phone: req.body.phone,
        job: req.body.work,
        workplace: req.body.workplace,
        age: req.body.age,
        favorite: req.body.favorite,
        yourself: req.body.yourself,
        security: req.body.security,
        income: req.body.income,
        alone: status
    });

    creatuser.save(function (err, data) {
        if (err) {
            res.json({
                kq: 0,
                ErrMess: 'Loi~ ne`=====> ' + err
            });
            console.log(err)
        } else {
            // console.log('New User registed thanh` cong` '+ data);
            res.render('home.ejs', { page: 'chat' });
        }
    })
});

//Login Chat-App
app.get('/login', function (req, res) {
    res.render('home.ejs', { page: 'login' })
})
//fetch user & check password by compare Pass from Linda's Mongoose DB
app.post('/login', async function (req, res) {
    var usercheck = await User.find({
        username: req.body.email,
    })
    // if tim k0 ra, bao sai email

    // const isMatchPasswod = await usercheck.comparePassword( req.body.pwd)

    // if k0 match passwod thi return loi


    // username: req.body.email,
    // password: req.body.pwd,

    //create tocken
    var tocken = jwt.sign({
        "User": usercheck.username,
        // "Password": usercheck.password
    }, secret, { expiresIn: 60 * 60 });
    console.log('TOCKEN NE`:' + tocken);

    //verify a tocken
    jwt.verify(tocken, secret, function (err, decoded) {
        if (err) {
            console.log('Tocken Loi~ kia')
        } else {
            //check user to database
            usercheck.save(function (err) {
                if (err) {//have ERRR
                    throw err
                } else {
                    //Authenticate user
                    User.getAuthenticated(decoded.User, decoded.Password, function (err, user, reason) {
                        if (err) {
                            throw err;
                        } else if (user) {
                            //login compelete if co' user
                            console.log('login compelete!!');
                            res.render('home.ejs', { page: 'chat' });
                            return;
                        } else {
                            //login failed & tim` nguyen nhan
                            var reasons = User.failedLogin;
                            switch (reasons) {
                                case reasons.NOT_FOUND:
                                case reasons.PASSWORD_INCORRECT:
                                    break;
                                case reasons.MAX_ATTEMPTS:
                                    //Warring with notification or email noti
                                    //locked all account
                                    break;
                            };
                        };
                    });
                };
            });
        }
    })
});

app.listen(port, console.log('Load compelete...!'))