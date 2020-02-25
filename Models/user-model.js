var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    bcrypt = require('bcrypt'),
    SALT_WORK_FACTOR = 10,
    MAX_LOGIN_ATTEMPTS = 5,
    LOCK_TIME = 1 * 60 * 60 * 1000; //2h => lock
const UserSchema = new Schema({
    username: { type: String, required: true, index: { unique: true } },
    password: {
        type: String,
        required: true,
    },
    fullname: {
        type: String,
    },
    location: {
        type: String,
    },
    phone: {
        type: String,
    },
    job: {
        type: String,
    },
    workplace: {
        type: String,
    },
    age: {
        type: Number,
    },
    favorite: {
        type: String,
    },
    yourself: {
        type: String,
    },
    security: {
        type: String,
    },
    income: {
        type: Number,
    },
    alone: {
        type: Boolean,
    },
    //write number of login Attempts liên tiếp
    loginAttempts: {
        type: Number,
        required: true,
        default: 0
    },
    //Until number of login Attempts, then lock
    lockUntil: {
        type: Number,
    }
});


UserSchema.virtual('isLocked').get(function () {
    // check for lockUntil timestamp
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

var jwt = require('jsonwebtoken');
var secret = ">SDsdungchoaibiet***";

UserSchema.pre('save', function (next) {
    var user = this;
    // only hash the password if it đã được modified
    if (!user.isModified('password')) return next();
    // gen a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err) return next(err);

        // hash the password
        bcrypt.hash(user.password, salt, function (err, hash) {
            if (err) return next(err);

            // set the hashed password back on our user document
            user.password = hash;

            //create tocken
            // var tocken = jwt.sign({
            //     "User": user.username,
            //     "Password": user.password
            // }, secret, { expiresIn: 60 * 60 });
            // console.log('TOCKEN NE`:' + tocken);

            next();
        });
    });
});

//Method: Check & compare password hiện tại with password hashed form Linda-DB
UserSchema.methods.comparePassword = function (candidatePassword, cb) {

    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

//Method: Process when have incLogin Attempts
UserSchema.methods.inloginAttempts = function login(cb) {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.update({
            //Attempts lần thứ 1 & Untill lần login thứ 1
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1 }
        }, cb);
    };
    // if đạt max attempts => lock the account
    var updates = {
        $in: {
            loginAttempts: 1
        }
    };
    if (this.loginAttempts + 1 > MAX_LOGIN_ATTEMPTS && !this.isLocked) {
        update.$set = {
            lockUntil: Date.now() + LOCK_TIME
        };
        // Lock sau khi thời gian (thời gian hiện tại + thời gian qui ước)
    }
    return this.update(updates, cb);
};

//Send confirm nguyên nhân failded login 

//Confirm kịch bản with var reasons
var reasons = UserSchema.statics.failedLogin = {
    NOT_FOUND: 0,
    PASSWORD_INCORRECT: 1,
    MAX_ATTEMPTS: 2
};

var authenticated = UserSchema.statics.getAuthenticated;
// Kịch bản phản hồi login
authenticated = function (username, password, cb) {
    this.findOne({ username: req.body.email }, function (err, user) {
        //HAVE ERRORS
        if (err) {
            //err: ví dụ => ko connect Linda database
            return cb(err);
        } else if (!user) {
            // account méo có
            return cb(null, null, reasons.NOT_FOUND);
        } else if (user.isLocked) {
            //account đã lock khi nhập quá lần
            return user.loginAttempts(function (err) {
                if (err) {
                    return cb(err);
                } else {
                    return cb(null, null, reasons.MAX_ATTEMPTS);
                };
            });
            // PASSWORD có TRÙNG KHỚP ?
        } else {
            user.comparePassword(password, function (err, isMatch) {
                if (err) {
                    return cd(err);
                } else if (isMatch) {
                    //Password isMatch trùng khớp
                    if (!user.loginAttempts && !user.lockUntil) {
                        //ko lock & faild Attempts
                        return cb(null, user);
                    } else {
                        //
                        var updates = {
                            $set: { loginAttempts: 0 },
                            $unset: { lockUntil: 1 }
                        };
                        return user.updates(updates, function (err) {
                            if (err) {
                                return cb(err);
                            } else {
                                return cb(null, user);
                            }
                        })
                    }
                } else {
                    //pas ko đúng => tăng số lần attempts
                    user.loginAttempts(function (err) {
                        if (err) {
                            return cb(err);
                        } else {
                            return cb(null, null, reasons.PASSWORD_INCORRECT);
                        }
                    });
                };
            });
        };
    });
};

const UserModel = mongoose.model('User', UserSchema);
module.exports = UserModel;