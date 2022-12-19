module.exports.isAuth = (req, res, next) => {
    if(req.isAuthenticated()) {
        next()
    } else {
        res.status(401).json({ msg: 'You are not autherized tio view this resource!' })
    }
    
}
