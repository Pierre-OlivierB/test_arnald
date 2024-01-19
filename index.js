const Jwt = require("jsonwebtoken");
const mysql = require("mysql");

const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");

const express = require("express");
const cors = require("cors");
const app = express();

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["POST", "GET", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(express.json());

app.use(cookieParser());

app.listen(3001, () => {
  console.log("server running on 3001");
});

const cost = 10;

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "films",
});

// *-------------Loggin
const checkUser = (req, res, next) => {
  const token = req.cookies.tokenco;
  Jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) {
      return res.json({ Message: "Erreur" });
    } else {
      req.name = decoded.name;
      req.role = decoded.role;
      next();
    }
  });
};
app.get("/", checkUser, (req, res) => {
  return res.json({ Status: "Ok", Nom: req.name, Role: req.role });
});
// *-----------------

app.get("/select", (req, res) => {
  const sql = "SELECT * FROM user";

  db.query(sql, (err, data) => {
    if (err) return app.json("error");
    return res.json(data);
  });
});

app.post("/createaccount", (req, res) => {
  bcrypt.hash(req.body.pass.toString(), cost, (err, hash) => {
    if (err) return res.json(console.log("Erreur de hashage"));

    const values = [req.body.name, req.body.email, hash];

    const sql = "INSERT INTO user(name,email,pwrd) VALUES(?)";

    db.query(sql, [values], (err, result) => {
      console.log(result);
      if (err) return res.json("error");
      return res.json(result);
    });
  });
});
app.post("/login", (req, res) => {
  const sql = "SELECT * FROM user WHERE email=?";
  db.query(sql, [req.body.email], (err, result) => {
    if (err) return res.json({ Error: "Un problème est survenu" });
    if (result.length > 0) {
      // console.log(req.body.pass);
      bcrypt.compare(req.body.pass.toString(), result[0].pwrd, (err, respo) => {
        // console.log(result[0].pwrd);
        if (err) return res.json({ Error: "Erreur connection" });
        if (respo) {
          const name = result[0].name;
          const role = result[0].role;
          console.log(role);
          const token = Jwt.sign({ name: name, role: role }, "jwt-secret-key", {
            expiresIn: "1d",
          });
          res.cookie("tokenco", token);
          return res.json({ Status: "Ok", token: token });
        } else return res.json({ Status: "erreur mot de pass" });
      });
    } else {
      return res.json({ Error: "Le compte n'existe pas" });
    }
  });
});
app.post("/create", (req, res) => {
  //   res.send("hello wolrd");
  const sql = "INSERT INTO user(name,email) VALUES(?)";
  // console.log(req, sql);
  const data = [req.body.name, req.body.email];

  db.query(sql, [data], (err, result) => {
    if (err) return res.json("error");
    // console.log(sql);
    return res.json(result);
  });
  // console.log("response ", req.body);
  // res.redirect("/");
});
app.put("/update/:id_user", (req, res) => {
  const sql = "UPDATE user SET name=?,email=? WHERE id_user=?";
  const data = [req.body.name, req.body.email];

  const idUser = req.params.id_user;
  db.query(sql, [...data, idUser], (err, result) => {
    if (err) return res.json("error");
    return res.json(result);
  });
});

app.delete("/delete/:id_user", (req, res) => {
  const sql = "DELETE FROM user WHERE id_user=?";
  const idUser = req.params.id_user;
  db.query(sql, [idUser], (err, result) => {
    if (err) return res.json("Error");
    return res.json(result);
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("tokenco");
  return res.json({ Status: "Ok" });
});
