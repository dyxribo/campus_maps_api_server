import express from "express";
import crypto from "crypto";
import sqlite3 from "sqlite3";
import argon2 from "argon2";
import cream from "dotenv";
import jwt from "jsonwebtoken";

cream.config();
sqlite3.verbose();

const app = express();
const db = new sqlite3.Database(process.env.usrdb_path);
const STATUS_UNUATHORIZED = 401;
const STATUS_SERVER_ERROR = 500;
const STATUS_OK = 200;

app.get("/", (req, res) => {
  res.send("<h1>hello from blaxstar!</h1>");
});

app.get("/api/login", (req, res) => {
  // first get the auth header and store it in a variable
  var ahead = req.header("Authorization");
  // get the b64 cred string as arr by splitting by space, then colon
  var crd = atob(ahead.split(" ")[1]).split(":");
  var usr = crd[0];
  var srt = crd[1];

  // get the user from the db and verify the srt
  db.serialize(
    () => {
      db.get(`SELECT * FROM usr_tbl WHERE username = "${usr}"`, (err, row) => {
        if (err) {
          res.send("<h1>USER_NOT_FOUND</h1>");
        } else {
          if (verify_srt(srt, row.srt)) {
            // generate new tokens if srt is valid
            var jwt_pld = {
              iss: `${usr}`,
              admin: `${row.adm}`,
              exp: Math.floor(Date.now() / 1000) + 60 * 1,
            };
            
            const at = sign_jwt(jwt_pld, "access");
            const rt = sign_jwt(jwt_pld, "refresh");

            if (at && rt) {
              // return new tokens
              res.setHeader("Authorization", `Bearer ${at}`);
              res.setHeader("X-REF-TOK", rt);
              res.status(STATUS_OK).send("OK");
            } else {
              // return error if new tokens could not be generated
              res.status(STATUS_SERVER_ERROR).send({
                err: "could not generate token, please try again later.",
              });
            }
          }
        }
      });
    } 
  );
});

app.post("/api/rftkn", (req, res) => {
  // get the auth header and verify refresh token
  const tkn = req.header("X-REF-TOK");
  const rt_pld = verify_jwt(tkn, "refresh");
  
  if (rt_pld) {
    // sign new tokens if the refresh token is valid
    let new_at = sign_jwt(rt_pld, "access");
    let new_rt = sign_jwt(rt_pld, "refresh");

    if (new_at && new_rt) {
      // return new tokens
      res.setHeader("Authorization", `Bearer ${new_at}`);
      res.setHeader("X-REF-TOK", new_rt);
      res.status(STATUS_OK).send("TKRF OK");
    } else {
      // return error if new tokens could not be generated
      res.status(STATUS_SERVER_ERROR).send({
        err: "could not generate token, please try again later.",
      });
    }
  } else {
    // return error if refresh token is invalid
    res.status(STATUS_UNUATHORIZED).send({
      err: "invalid refresh token, please log in again.",
    });
  }
});

app.get("/api/logout", (req, res) => {
  res.status(STATUS_OK).send("OK");
});

app.get("/api/maps", () => {
  res.status(STATUS_OK).send("OK");
});

app.listen(5000, () => {
  console.log("server listening on port 5000.");
});

async function verify_srt(srt, hash) {
  // verify the srt using argon2
  if (await argon2.verify(hash, srt)) {
    return true;
  }
  return false;
}

async function hash_srt(srt) {
  // hash the srt using argon2
  const hash_options = {
    type: argon2.argon2id,
    tagLength: 32,
  };
  return await argon2.hash(srt, hash_options);
}

function sign_jwt(pld, tkn_type, options) {
  // check the token type and update the payload accordingly
  if (tkn_type == "access") {
    // 1 min access token TODO: change back to 15 min
    pld.exp = Math.floor(Date.now() / 1000) + 60 * 1;
  } else if (tkn_type == "refresh") {
    // 1 min refresh token TODO: change back to 1 hr
    pld.exp = Math.floor(Date.now() / 1000) + 60 * 1;
  } else {
    // invalid token type
    console.log("invalid token type @ sign_jwt ln 119!");
    return null;
  }

  // create a buffer using the private key and convert it to ascii
  const pk = Buffer.from(
    tkn_type == "access" ? process.env.atpk : process.env.rtpk,
    "base64"
  ).toString("ascii");
  // sign the payload with the private key
  return jwt.sign(pld, pk, { ...(options && options), algorithm: "RS256" });
}

function verify_jwt(tkn, tkn_type) {
  // check the token type and use the appropriate key 
  let tknkey;
  if (tkn_type == "access") {
    tknkey = process.env.atpbk;
  } else if (tkn_type == "refresh") {
    tknkey = process.env.rtpbk;
  } else {
    console.log("invalid token type @ verify_jwt ln 138!");
    return null;
  }

  try {
    // create a buffer using the public key and convert it to ascii
    const pbk = Buffer.from(tknkey, "base64").toString("ascii");
    // verify the token with the public key
    const decoded = jwt.verify(tkn, pbk);
    // return the decoded payload
    return decoded;
  } catch (e) {
    // log the error
    console.log(e.message ? e.message : e);
    // return null if the token could not be verified
    return null;
  }
}
