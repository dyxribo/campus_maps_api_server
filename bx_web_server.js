import express from "express";
import crypto from "crypto";
import sqlite3 from "sqlite3";
import argon2 from "argon2";
import cream from "dotenv";
import jwt from "jsonwebtoken";
// cash rules everything around me!
cream.config();
sqlite3.verbose();

const app = express();
const user_database = new sqlite3.Database(process.env.usrdb_path);
// status codes
const STATUS_UNUATHORIZED = 401;
const STATUS_SERVER_ERROR = 500;
const STATUS_OK = 200;

app.get("/", (request_data, response_data) => {
  response_data.status(STATUS_OK).send("<h1>hello from blaxstar!</h1>");
});

app.get("/api/login", (request_data, response_data) => {
  // first get the auth header and store it in a variable
  var authorization_header = request_data.header("Authorization");
  // get the b64 cred string as arr by splitting by space, then colon
  var credentials = atob(authorization_header.split(" ")[1]).split(":");
  var username = credentials[0];
  var secret = credentials[1];

  // get the user from the db and verify the secret
  user_database.serialize(
    () => {
      user_database.get(`SELECT * FROM usr_tbl WHERE username = "${username}"`, (query_error, result_row) => {
        if (query_error) {
          response_data.status(STATUS_UNUATHORIZED).send({message: "user not found"});
        } else {
          if (verify_secret(secret, result_row.secret)) {
            // generate new tokens if secret is valid
            var jwt_payload = {
              iss: `${username}`,
              admin: `${result_row.adm}`,
              exp: Math.floor(Date.now() / 1000) + 60 * 1,
            };
            
            const access_token = sign_jwt(jwt_payload, "access");
            const refresh_token = sign_jwt(jwt_payload, "refresh");

            if (access_token && refresh_token) {
              // return new tokens
              response_data.setHeader("Authorization", `Bearer ${access_token}`);
              response_data.setHeader("X-REF-TOK", refresh_token);
              response_data.status(STATUS_OK).send("OK");
            } else {
              // return error if new tokens could not be generated
              response_data.status(STATUS_SERVER_ERROR).send({
                message: "could not generate token, please try again later.",
              });
            }
          }
        }
      });
    } 
  );
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
  response_data.status(STATUS_OK).send("OK");
});

app.get("/api/maps", () => {
  res.status(STATUS_OK).send("OK");
});

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
  return await argon2.hash(secret, hash_options);
}

function sign_jwt(token_payload, token_type, options) {
  // check the token type and update the payload accordingly
  if (token_type == "access") {
    // 1 min access token TODO: change back to 15 min
    token_payload.exp = Math.floor(Date.now() / 1000) + 60 * 1;
  } else if (token_type == "refresh") {
    // 1 min refresh token TODO: change back to 1 hr
    token_payload.exp = Math.floor(Date.now() / 1000) + 60 * 1;
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
  return jwt.sign(token_payload, private_key, { ...(options && options), algorithm: "RS256" });
}

function verify_jwt(token, token_type) {
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
