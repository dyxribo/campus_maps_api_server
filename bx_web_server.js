import express from "express";
import bp from "body-parser";
import Database from "better-sqlite3";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import path from "node:path";
import { flatten, unflatten } from "flat";

// config
dotenv.config({ path: path.resolve('/srv/blaxstar_web/.env'), override: true });
const env = process.env;
const port = 5000;
const app = express();

// databases
const user_database = new Database(path.resolve(env.userdb_file));
const token_denylist_database = new Database(path.resolve(env.token_denylistdb_file));
const maps_database = new Database(path.resolve(env.mapdb_file));
// status codes
const STATUS_UNUATHORIZED = 401;
const STATUS_NOT_FOUND = 404;
const STATUS_SERVER_ERROR = 500;
const STATUS_OK = 200;
// set journal mode for better database performance
user_database.pragma("journal_mode = WAL");
token_denylist_database.pragma("journal_mode = WAL");
maps_database.pragma("journal_mode = WAL");
// parse url encoded variables and json body from incoming requests
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


// ********** //
// * ROUTES * //
// ********** //


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
  response_data.status(STATUS_OK).send('<h1>Account activation complete! you can now close this window. :)</h1>');
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

    if (!validated_user) {
      response_data
        .status(STATUS_UNUATHORIZED)
        .send({ message: "user not found" });
    }
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
          response_data.status(STATUS_OK).send({ username: jwt_payload.iss, admin: jwt_payload.admin });
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
    // disable the currently used refresh token
    revoke_token(client_token, client_token_payload.exp);
    // sign new tokens if the refresh token is valid
    let new_access_token = sign_jwt(client_token_payload, "access");
    let new_refresh_token = sign_jwt(client_token_payload, "refresh");

    if (new_access_token && new_refresh_token) {
      // return new tokens
      response_data.setHeader("Authorization", `Bearer ${new_access_token}`);
      response_data.setHeader("X-REF-TOK", new_refresh_token);
      response_data.status(STATUS_OK).send({ username: client_token_payload.iss, admin: client_token_payload.admin });
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
  const client_auth_token = request_data.header("Authorization").split(' ')[1];
  const client_refresh_token = request_data.header("X-REF-TOK");
  const auth_token_payload = verify_jwt(client_auth_token, "access");
  const refresh_token_payload = verify_jwt(client_refresh_token, "refresh");

  // add token to denylist database to prevent login with same token
  if (auth_token_payload) {
    revoke_token(client_auth_token, auth_token_payload.exp);
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
  const client_auth_token = request_data.header("Authorization").split(' ')[1];
  const auth_token_payload = verify_jwt(client_auth_token, "access");

  if (!auth_token_payload) {
    response_data.status(STATUS_UNUATHORIZED).send({
      message: "invalid access token, please log in again.",
    });
    return;
  }

  let updated_map_data = update_client_map(request_data.query.last_modified);

  response_data.status(updated_map_data.status).send(updated_map_data);

});

app.post("/api/postmap", (request_data, response_data) => {
  // first verify the access token from the auth header to make sure we can do this
  const client_auth_token = request_data.header("Authorization").split(' ')[1];
  const auth_token_payload = verify_jwt(client_auth_token, "access");
  if (!auth_token_payload) {
    response_data.status(STATUS_UNUATHORIZED).send({
      message: "invalid access token, please log in again.",
    });
    return;
  }

  let update_status = update_server_map(request_data.body.last_modified, request_data.body.map_data);
  response_data.status(update_status.status).send(update_status);
})


// ******************** //
// * HELPER FUNCTIONS * //
// ******************** //

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
    console.log("invalid token type @ sign_jwt ln 284!");
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
    console.log("invalid token type @ verify_jwt ln 316!");
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

function revoke_token(token, exp) {
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

  if (activation_token_payload) {
    // get the username from the payload
    const username = activation_token_payload.username;

    // lets make sure the user is not already activated
    const user_row = user_database.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (user_row.activated) {
      // disable the token used to make this request
      console.log("user already active. token denylist success.");
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

function update_server_map(client_mod_date, client_changes) {
  
  let update_status = { status: STATUS_OK };
  let database_map_row;
  let database_map;
  let flattened_changes;

  try {
    // first check the db against the modification date for the incoming data
    database_map_row = maps_database.prepare("SELECT * from map_data WHERE modified_date < ?").get(client_mod_date);
  } catch (e) {
    update_status.status = STATUS_SERVER_ERROR;
    update_status["error"] = e;
    return update_status;
  }

  if (database_map_row) {
    // if the check was successful, we flatten the json from the db for easy comparison
    database_map = flatten(JSON.parse(database_map_row.data));
  } else {
    // otherwise we send back an error
    update_status.status = STATUS_SERVER_ERROR;
    update_status['error'] = "newer changes on server, pending client sync. please send another request to update database after syncing.";
    update_status['data'] = maps_database.prepare("SELECT data from map_data").get().data;
    return update_status;
  }
  // flatten the the incoming changes for easy comparison
  flattened_changes = flatten(client_changes);
  let changed_properties = Object.keys(flattened_changes);
  // compare the incoming changes to the db and update the db json
  for (let property_name of changed_properties) {
    database_map[property_name] = flattened_changes[property_name];
  }
  // then write the json back to the db, updating the modify date as well
  update_map_db('map_data', JSON.stringify(unflatten(database_map)), Date.now() / 1000);
  update_status['data'] = unflatten(database_map);

  return update_status;
}

function update_client_map(client_mod_date) {
  // we'll use a json object for storing the updates.
  var update_status = { status: STATUS_OK };
  
  update_status['data'] = maps_database.prepare("SELECT data from map_data").get().data;

  return update_status;
}

// not used, included for example
function insert_into_map_db(table, ...values) {
  let status = { status: STATUS_OK };
  try {
    maps_database.prepare("INSERT INTO " + table + " VALUES (" + values.join(',') + ")").run();
  } catch (error) {
    status.status = STATUS_SERVER_ERROR;
    status['error'] = error;
  }
  return status;
}

function update_map_db(table, ...values) {
  
  let status = { status: STATUS_OK };
  
  if (values.length < 2) {
    status.status = STATUS_SERVER_ERROR;
    status.error = "got " + values.length + " values for map db update, expected 2.";
    return status;
  }

  try {
    // for the test db, there is only 2 columns, the data and modified date. these will be updated when a postmap request is made. modify as needed.
    let statement = "UPDATE " + table + " SET data = '" + String(values[0]) + "', modified_date = " + Math.floor(values[1]);
    maps_database.prepare(statement).run();
  } catch (error) {
    status.status = STATUS_SERVER_ERROR;
    status['error'] = error;
  }
  return status;
}

app.listen(port, () => {
  console.log(`server listening on port ${port}.`);
});