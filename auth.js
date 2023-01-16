const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
};

const hashPassword = (req, res, next) => {
  argon2
    .hash(req.body.password, hashingOptions)
    .then((hashedPassword) => {
      req.body.hashedPassword = hashedPassword;
      delete req.body.password;

      next();
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

const verifyPassword = (req, res) => {
  const { password } = req.body;
  const { hashedPassword, id } = req.user;

  argon2
    .verify(hashedPassword, password)
    .then((match) => {
      if (match) {
        const payload = { sub: id };

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        delete req.user.hashedPassword;

        res.send({ token, user: req.user });
      } else {
        res.sendStatus(401);
      }
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

const auth = (req, res, next) => {
  const { email, password } = req.body;
  console.log(email, password);
  if (email === "email@mail.com" && password === "pass") {
    res.send("Credentials are valid");
    next();
  } else {
    res.sendStatus(401);
  }
};

const verifyToken = (req, res, next) => {
  try {
    const authorizationHeader = req.get("Authorization");

    if (authorizationHeader == null) {
      throw new Error("Authorization header is missing");
    }
    const [type, token] = authorizationHeader.split(" ");
    if (type !== "Bearer") {
      throw new Error("Authorization header has not the 'Bearer' type");
    }
    req.payload = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

const verifyId = (req, res, next) => {
  try {
    if (req.payload.sub === parseInt(req.params.id)) {
      next();
    } else {
      res.sendStatus(403);
    }
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
  verifyId,
  auth, // don't forget to export
};
