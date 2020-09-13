const express = require("express");
const mysql = require("mysql");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const { response } = require("express");
const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);

dotenv.config({ path: "./.env" });
app.use(express.static("public"));

//show login file
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/views/login.html");
});

//show register file
app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/views/register.html");
});
//show user file after user logs in
app.get("/user", (req, res) => {
  res.sendFile(__dirname + "/views/user.html");
});

const urlencodedParser = bodyParser.urlencoded({ extended: false });
app.use(express.json());
app.use(cookieParser());
var connection = mysql.createConnection(options);
var sessionStore = new MySQLStore({ options }, connection, (error, results) => {
  if (error) {
    console.log(error);
  } else console.log("connection for session created");
});

//database connection
const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

db.connect((error) => {
  if (error) {
    console.log(error);
  } else console.log("mysql is connected..");
});

var options = {
  host: process.env.DATABASE_HOST,
  port: process.env.DATABASE_PORT,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
};

app.use(
  session({
    key: "session_cookie_name",
    secret: "session_cookie_secret",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    schema: {
      tableName: "sessions",
      columnNames: {
        session_id: "session_id",
        expires: "expires",
        data: "data",
      },
    },
  })
);

//user registration
app.post(
  "/register",
  /*urlencodedParser,*/ async (req, res) => {
    console.log(req.body);

    const { email, password, passwordConfirm } = req.body;

    db.query(
      "SELECT email FROM users WHERE email = ?",
      [email],
      async (error, result) => {
        if (error) {
          console.log(error);
        } else {
          if (result.length > 0) {
            return res.json({
              message: "This email has already been registered",
            });
          } else {
            try {
              let hashedPassword = await bcrypt.hash(password, 8);
              console.log(hashedPassword);
              db.query(
                "INSERT INTO users SET ?",
                { email: email, password: hashedPassword },
                (error, results) => {
                  if (error) {
                    console.log(console.log(error));
                    return;
                  } else {
                    console.log(results);
                    res.redirect("/user");
                    return;
                  }
                }
              );
            } catch (err) {
              console.log(err);
            }
          }
        }
      }
    );
  }
);

//user login
app.post("/login", urlencodedParser, async (req, res) => {
  const { email, password } = req.body;
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (error, result) => {
      if (error) {
        console.log(error);
      } else {
        try {
          if (result.length === 0 || !result) {
            res.json({ message: "Email has not been registered" });
          } else {
            bcrypt.compare(password, result[0].PASSWORD, (err, results) => {
              if (err) {
                console.log(err);
                return res.json({
                  message: "there has been some problem matching the password",
                });
              } else {
                if (results) {
                  //cookie creation
                  /*const id = result[0].id;
                  const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN,
                  });

                  console.log("the token is " + token);

                  const cookieOptions = {
                    expires: new Date(
                      Date.now() +
                        process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                    ),
                    httpOnly: true,
                  };

                  res.cookie("myCookieJwt", token, cookieOptions);*/
                  res.status(200).redirect("/user");
                } else {
                  res.json({ message: "Please enter correct password" });
                }
              }
            });
          }
        } catch (error) {
          console.log(error);
          return;
        }
      }
    }
  );
});

//app listening
const listener = app.listen(process.env.PORT || 3000, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
