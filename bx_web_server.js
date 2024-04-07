import express from "express";
import crypto from "crypto";
import sqlite3 from "sqlite3";
import argon2 from "argon2";
import cream from "dotenv";
import jwt from "jsonwebtoken";

cream.config();
sqlite3.verbose();

const app = express();
const db = new sqlite3.Database("C:\\eng\\js\\cm_users.db");

app.get("/", (req, res) => {
  res.send("<h1>hello from blaxstar!</h1>");
});

app.get("/login", (req, res) => {
  // first get the auth header and store it in a variable
  var ahead = req.header("Authorization");
  // get the b64 cred string as arr
  var crd = atob(ahead.split(" ")[1]).split(":");
  var usr = crd[0];
  var srt = crd[1];
  // hash the srt for comparison
  const salt = crypto.randomBytes(16);

  // get the user from the db
  db.serialize(
    () => {
      db.get(`SELECT * FROM usr_tbl WHERE username = "${usr}"`, (err, row) => {
        if (err) {
          res.send("<h1>USER_NOT_FOUND</h1>");
        } else {
          if (verify_srt(srt, row.srt)) {
            var jwt_pld = {
              iss: `${usr}`,
              admin: `${row.adm}`,
              exp: Math.floor(Date.now() / 1000) + 60 * 1,
            };

            const at = sign_jwt(jwt_pld, "access");
            const rt = sign_jwt(jwt_pld, "refresh");

            // send the items to the client in the form of a jwt
            if (at && rt) {
              res.setHeader("Authorization", `Bearer ${at}`);
              res.setHeader("X-REF-TOK", rt);
              res.status(200).send("OK");
            } else {
              res.send({
                err: "could not generate token, please try again later.",
              });
            }
          }
        }
      });
      // if the user exists, get the user's items from the db
    } // we'll need to send a jwt, so define the header and body
  );
});

app.post("/rftkn", (req, res) => {
  // get the auth header and store it in a variable
  var tkn = req.header("X-REF-TOK");
  // get the b64 cred string as arr

  const rt_pld = verify_jwt(tkn, "refresh");
  // TODO: generate new tokens if refresh token is valid, otherwise return expired response, forcing user to log back in
  if (rt_pld) {
    console.log("✅Refresh token is valid!");
  } else {
    console.log("🔥Refresh token is invalid or has expired!");
  }
});

app.listen(5000, () => {
  console.log("server listening on port 5000.");
});

async function verify_srt(srt, hash) {
  if (await argon2.verify(hash, srt)) {
    return true;
  }
  return false;
}

async function hash_srt(srt) {
  const hash_options = {
    type: argon2.argon2id,
    tagLength: 32,
  };
  return await argon2.hash(srt, hash_options);
}

function sign_jwt(pld, tkn_type, options) {
  if (tkn_type == "access") {
    // 15 min access token
    pld.exp = Math.floor(Date.now() / 1000) + 60 * 15;
  } else if (tkn_type == "refresh") {
    // 1 hr refresh token
    pld.exp = Math.floor(Date.now() / 1000) + 60 * 60;
  } else {
    console.log("invalid token type @ sign_jwt ln 108!");
    return null;
  }

  const pk = Buffer.from(
    tkn_type == "access" ? process.env.atpk : process.env.rtpk,
    "base64"
  ).toString("ascii");

  return jwt.sign(pld, pk, { ...(options && options), algorithm: "RS256" });
}

function verify_jwt(tkn, tkn_type) {
  var tknkey;
  if (tkn_type == "access") {
    tknkey = process.env.atpbk;
  } else if (tkn_type == "refresh") {
    tknkey = process.env.rtpbk;
  } else {
    console.log("invalid token type @ verify_jwt ln 127!");
    return null;
  }

  try {
    const pbk = Buffer.from(tknkey, "base64").toString("ascii");
    const decoded = jwt.verify(tkn, pbk);
    return decoded;
  } catch (e) {
    if (e.message == "jwt expired") {
      console.log("token expired!");
      return null;
    } else if (e.message == "invalid token") {
      console.log("invalid token!");
      return null;
    }
    return null;
  }
}
