const mongoose = require("mongoose");
const User = mongoose.model("User");
const bcrypt = require("bcryptjs");

exports.verificationCheck = (req, res, next) => {
  User.aggregate([
    {
      $match: {
        $or: [{ email: req.body.email }, { username: req.body.email }],
      },
    },
    {
      $project: {
        password: 1,
        activated: 1,
      },
    },
  ])
    .then((users) => {
      if (users.length < 1) {
        return res.status(400).json({ message: "Usuario no encontrado" });
      } else {
        bcrypt.compare(req.body.password, users[0].password, (err, result) => {
          if (err) {
            return res.status(400).json({ message: "Ha ocurrido un error inesperado" });
          }
          if (result) {
            if (!users[0].activated) {
              return res.status(400).json({ message: "La cuenta no ha sido activada." });
            }
            return next();
          }
          return res.status(400).json({ message: "Contraseña incorrecta" });
        });
      }
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ message: err });
    });
};
