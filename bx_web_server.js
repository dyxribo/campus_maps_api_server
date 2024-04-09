import express from "express";
import bp from "body-parser";
import Database from "better-sqlite3";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const env = process.env;
const app = express();
const user_database = new Database(env.userdb_file);
const token_denylist_database = new Database(env.token_denylistdb_file);
const maps_database = new Database(env.mapdb_file);
// status codes
const STATUS_UNUATHORIZED = 401;
const STATUS_NOT_FOUND = 404;
const STATUS_SERVER_ERROR = 500;
const STATUS_OK = 200;

user_database.pragma("journal_mode = WAL");
token_denylist_database.pragma("journal_mode = WAL");

app.use(
  bp.urlencoded({
    extended: true,
    limit: "50mb",
    parameterLimit: 100000,
  })
);
app.use(
  bp.json({
    limit: "50mb",
    parameterLimit: 100000,
  })
);

app.get("/", (request_data, response_data) => {
  response_data.status(STATUS_OK).send("<h1>hello from blaxstar!</h1>");
});

app.post("/api/register", (request_data, response_data) => {
  // get the username and secret from the request body
  const username = request_data.body.username;
  const secret = request_data.body.secret;
  const email = request_data.body.email;
  // hash the secret
  hash_secret(secret).then((hashed_secret) => {
    // insert the user into the database
    try {
      let result_row = user_database
        .prepare("SELECT * FROM users WHERE username = ? OR email = ?")
        .get(username, email);

      if (result_row) {
        // if user or email already exists return error
        response_data.status(STATUS_UNUATHORIZED).send({
          message: "user or email already exists.",
        });
      } else {
        // if user or email does not exist insert user
        try {
          user_database
            .prepare(
              "INSERT INTO users (username, srt, adm, email, activated) VALUES (?, ?, ?, ?, ?)"
            )
            .run(username, hashed_secret, "0", email, "0");
        } catch (error) {
          response_data.status(STATUS_SERVER_ERROR).send({
            message: "server database error, please try again later. " + error,
          });
        }
        // send activation email if user was inserted and return success
        send_activation_email(email, username);
        response_data
          .status(STATUS_OK)
          .send("registration ok, please check email for activation link.");
      }
    } catch (error) {
      response_data.status(STATUS_SERVER_ERROR).send({
        message: "server database error, please try again later. " + error,
      });
    }
  });
});

app.get("/activate", (request_data, response_data) => {
  const activation_token = request_data.query.at;
  activate_user(activation_token);
  response_data.status(STATUS_OK).send('<script>window.location="https://blaxstar.net"</script>');
});

app.post("/api/login", (request_data, response_data) => {
  // first get the auth header and store it in a variable
  var authorization_header = request_data.header("Authorization");
  // get the b64 cred string as arr by splitting by space, then colon
  var credentials = atob(authorization_header.split(" ")[1]).split(":");
  var username = credentials[0];
  var secret = credentials[1];

  // get the user from the db and verify the secret
  try {
    let validated_user = user_database
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username);

    verify_secret(secret, validated_user.srt).then((match) => {
      if (!match) {
        response_data
          .status(STATUS_UNUATHORIZED)
          .send({ message: "user not found" });
      } else if (validated_user.activated != "1") {
        // send activation email if user was inserted and return success
        send_activation_email(validated_user.email, username);
        response_data
          .status(STATUS_UNUATHORIZED)
          .send({ message: "user not activated, email sent" });
      } else {
        // generate new tokens if secret is valid and user is activated
        var jwt_payload = {
          iss: username,
          admin: validated_user.adm,
          exp: Math.floor(Date.now() / 1000) + 60 * 1,
        };

        const access_token = sign_jwt(jwt_payload, "access");
        const refresh_token = sign_jwt(jwt_payload, "refresh");

        if (access_token && refresh_token) {
          // return new tokens
          response_data.setHeader("Authorization", `Bearer ${access_token}`);
          response_data.setHeader("X-REF-TOK", refresh_token);
          response_data.status(STATUS_OK).send("LOGIN OK");
        } else {
          // return error if new tokens could not be generated
          response_data.status(STATUS_SERVER_ERROR).send({
            message: "could not generate token, please try again later.",
          });
        }
      }
    });
  } catch (error) {
    response_data.status(STATUS_SERVER_ERROR).send({
      message: "server database error, please try again later. " + error,
    });
  }
});

app.post("/api/rftkn", (request_data, response_data) => {
  // get the auth header and verify refresh token
  const client_token = request_data.header("X-REF-TOK");
  const client_token_payload = verify_jwt(client_token, "refresh");

  if (client_token_payload) {
    // sign new tokens if the refresh token is valid
    let new_access_token = sign_jwt(client_token_payload, "access");
    let new_refresh_token = sign_jwt(client_token_payload, "refresh");

    if (new_access_token && new_refresh_token) {
      // return new tokens
      response_data.setHeader("Authorization", `Bearer ${new_access_token}`);
      response_data.setHeader("X-REF-TOK", new_refresh_token);
      response_data.status(STATUS_OK).send("TOKEN REFRESH OK");
    } else {
      // return error if new tokens could not be generated
      response_data.status(STATUS_SERVER_ERROR).send({
        message: "could not generate token, please try again later.",
      });
    }
  } else {
    // return error if refresh token is invalid
    response_data.status(STATUS_UNUATHORIZED).send({
      message: "invalid refresh token, please log in again.",
    });
  }
});

app.get("/api/logout", (request_data, response_data) => {
  const client_auth_token = request_data.header("Authorization");
  const client_refresh_token = request_data.header("X-REF-TOK");
  const auth_token_payload = verify_jwt(client_auth_token, "access");
  const refresh_token_payload = verify_jwt(client_refresh_token, "refresh");

  // add token to denylist database to prevent login with same token
  if (auth_token_payload) {
    token_denylist_database
      .prepare("INSERT INTO denied_tkns values (?, ?)")
      .run(client_auth_token, auth_token_payload.exp);
  }

  if (refresh_token_payload) {
    token_denylist_database
      .prepare("INSERT INTO denied_tkns values (?, ?)")
      .run(client_refresh_token, refresh_token_payload.exp);
  }

  response_data.status(STATUS_OK).send({ message: "LOGOUT OK" });
});

app.get("/api/getmap", (request_data, response_data) => {
  // first verify the access token from the auth header to make sure we can do this
    const client_auth_token = request_data.header("Authorization");
    const auth_token_payload = verify_jwt(client_auth_token, "access");
    if (!auth_token_payload) {
      response_data.status(STATUS_UNUATHORIZED).send({
        message: "invalid access token, please log in again.",
      });
      return;
    }

    // retrieve data from maps db using the map name from the request body
    try {
      let result_row = maps_database
        .prepare("SELECT * FROM maps WHERE map_name = ?")
        .get(request_data.query.map_name);

      if (!result_row) {
        // if map does not exist return error
        response_data.status(STATUS_NOT_FOUND).send({
          message: "map does not exist.",
        });
      } else {
        // if map exists return map data
        response_data.status(STATUS_OK).send(result_row.map_data);
      }
    } catch (error) {
      response_data.status(STATUS_SERVER_ERROR).send({
        message: "server database error, please try again later. " + error,
      });
    }
});

app.post("/api/postmap", (request_data, response_data) => {
  // first verify the access token from the auth header to make sure we can do this
  const client_auth_token = request_data.header("Authorization");
  const auth_token_payload = verify_jwt(client_auth_token, "access");
  if (!auth_token_payload) {
    response_data.status(STATUS_UNUATHORIZED).send({
      message: "invalid access token, please log in again.",
    });
    return;
  }
  // get json data from request and try to save it to maps db
  try {
    maps_database
      .prepare("INSERT INTO maps (map_name, map_data) VALUES (?, ?)")
      .run(request_data.body.map_name, request_data.body.map_data);
  } catch (error) {
    response_data.status(STATUS_SERVER_ERROR).send({
      message: "server database error, please try again later. " + error,
    });
    return;
  }
  response_data.status(STATUS_OK).send("POST MAP OK");
})

app.listen(5000, () => {
  console.log("server listening on port 5000.");
});

async function verify_secret(request_secret, hashed_secret) {
  // verify the secret using argon2
  if (await argon2.verify(hashed_secret, request_secret)) {
    return true;
  }
  return false;
}

async function hash_secret(secret) {
  // hash the secret using argon2
  const hash_options = {
    type: argon2.argon2id,
    tagLength: 32,
  };
  console.log(secret);
  return await argon2.hash(secret, hash_options);
}

function sign_jwt(token_payload, token_type, options) {
  // check the token type and update the payload accordingly
  if (token_type == "access") {
    // 1 min access token TODO: change back to 15 min
    token_payload.exp = Math.floor(Date.now() / 1000) + 60 * env.at_exp;
  } else if (token_type == "refresh") {
    // 1 min refresh token TODO: change back to 1 hr
    token_payload.exp = Math.floor(Date.now() / 1000) + 60 * env.rt_exp;
  } else {
    // invalid token type
    console.log("invalid token type @ sign_jwt ln 119!");
    return null;
  }

  // create a buffer using the private key and convert it to ascii
  const private_key = Buffer.from(
    token_type == "access" ? process.env.atpk : process.env.rtpk,
    "base64"
  ).toString("ascii");
  // sign the payload with the private key
  return jwt.sign(token_payload, private_key, {
    ...(options && options),
    algorithm: "RS256",
  });
}

function verify_jwt(token, token_type) {
  // before we do anything, lets make sure that the token was not denylisted
  let is_denylisted = verify_denylist_status(token);

  // if the token is denylisted, return null
  if (is_denylisted) {
    console.log("token is denylisted");
    return null;
  }
  // check the token type and use the appropriate key
  let rsa_key;
  if (token_type == "access") {
    rsa_key = process.env.atpbk;
  } else if (token_type == "refresh") {
    rsa_key = process.env.rtpbk;
  } else {
    console.log("invalid token type @ verify_jwt ln 138!");
    return null;
  }

  try {
    // create a buffer using the public key and convert it to ascii
    const public_key = Buffer.from(rsa_key, "base64").toString("ascii");
    // verify the token with the public key
    const decoded_token = jwt.verify(token, public_key);
    // return the decoded payload
    return decoded_token;
  } catch (e) {
    // log the error
    console.log(e.message ? e.message : e);
    // return null if the token could not be verified
    return null;
  }
}

function verify_denylist_status(token) {
  const token_row = token_denylist_database
    .prepare("SELECT * FROM denied_tkns WHERE token = ?")
    .get(token);

  if (token_row) {
    // check expiration of the original token and remove it from the database when it expires
    if (token_row.exp < Math.floor(Date.now() / 1000)) {
      token_denylist_database
        .prepare("DELETE FROM denied_tkns WHERE token = ?")
        .run(token);
    }
    // return true since the token was denylisted
    return true;
  }
  return false;
}

function denylist_token(token, exp) {
  try {
    token_denylist_database
    .prepare("INSERT INTO denied_tkns values (?, ?)")
    .run(token, exp);
  } catch (e) {
    console.log(e);
    return false
  }
  return true;
}

async function send_activation_email(email, username) {
  // create a transporter using the gmail smtp server
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      type: "OAuth2",
      user: process.env.mailer_email_address,
      serviceClient: process.env.mailer_clientid,
      privateKey: process.env.mailer_pk,
    },
  });

  // create the payload for the activation token
  const activation_token_payload = {
    username: username,
  };

  // sign the activation token
  const activation_token = sign_jwt(activation_token_payload, "access");

  // add the activation token to the url
  const activation_url = `https://blaxstar.net/activate?at=${activation_token}`;

  console.log(activation_url);
  // create the email content
  const mail_options = {
    from: process.env.mailer_email_address,
    to: email,
    subject: "Campus Maps Account Activation",
    text: `Hello ${username},\n\nplease click the following link to activate your campus maps account:\n\n${activation_url}\n\nThank you for using Campus Maps!\n\nDeron Decamp, Campus Maps Developer`,
  };

  // send the email
  try {
    await transporter.verify();
    transporter.sendMail(mail_options, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log("email sent: " + info.response);
      }
    });
  } catch (e) {
    console.log(e);
  }
}

async function activate_user(activation_token) {
  const activation_token_payload = verify_jwt(activation_token, "access");
  console.log(activation_token_payload);
  if (activation_token_payload) {
    // get the username from the payload
    const username = activation_token_payload.username;

    // lets make sure the user is not already activated
    const user_row = user_database.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (user_row.activated) {
      // disable the token used to make this request
      console.log("user already active. token denylist success : " + denylist_token(activation_token, activation_token_payload.exp));
      return;
    }

    try {
      // update the user in the database
      let user_activated = user_database
        .prepare("UPDATE users SET activated = 1 WHERE username = ?")
        .run(username);
        console.log("USER ACTIVATION OK");
    } catch (e) {
      console.log(e);
    }
  }
}
