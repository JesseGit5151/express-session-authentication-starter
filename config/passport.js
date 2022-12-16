const passport = require('passport');
const { validPassword } = require('../lib/passwordUtils');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;

const customFields = {
    usernameField: 'uname',
    passwordField: 'pw'
}

//Passport setup
const verifyCallback = (username, password, done) => {
    try {
        User.findOne({ username: username })
            .then((user) => {
                if(!user) {
                    return done(null, false)
                }

                const isValid = validPassword(password, user.hash, user.salt)

                if(isValid) {
                    return done(null, user)
                } else {
                    return done(null, false)
                }
            })
    } catch (error) {
        done(error)
    }
        
}
const strategy = new LocalStrategy(customFields, verifyCallback)

// TODO: passport.use();
passport.use(strategy);

passport.serializeUser((user, done) => {
    done(null, user.id)
})

passport.deserializeUser((userId, done) => {
    User.findById(userId)
    .then((user) => {
        done(null, user)
    })
    .catch(error => done(error))
})