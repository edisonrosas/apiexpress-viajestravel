const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  try {
    //const token = req.token;
    const token = req.get("Authorization").split(" ")[1];
    /*console.log("tok"+ token)
    console.log("tok2"+ process.env.JWT_KEY)
    console.log("bool"+JSON.stringify(jwt.verify(token, process.env.JWT_KEY)));*/
    const decoded = jwt.verify(token, process.env.JWT_KEY);
    req.userData = decoded;
    console.log("ok")
    //console.log(req)
    next();
  } catch (err) {
    //console.log("error con")
    return res.status(401).json({
      message: "Invalid token",
    });
  }
};
