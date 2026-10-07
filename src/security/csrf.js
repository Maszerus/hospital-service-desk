const crypto=require('crypto');
function token(req){ if(!req.session.csrfToken) req.session.csrfToken=crypto.randomBytes(24).toString('hex'); return req.session.csrfToken; }
function verify(req,res,next){ if(req.app.locals.isSecure && (!req.body.csrfToken || req.body.csrfToken!==req.session.csrfToken)) return res.status(403).send('403 Forbidden - invalid CSRF token'); next(); }
module.exports={token,verify};
