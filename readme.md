# CAMPUS MAPS EXAMPLE API SERVER

this repository hosts an example API for [Campus Maps](https://github.com/dyxribo/campus_maps_desktop).

written in javascript using node + express, this was a simple example of an API that leverages JSON web tokens (JWTs) for authorization and authentication. you can use this repo as a template and create your own custom API for your own use cases if needed.

for the databases, this repo uses SQLite3 ([download](https://www.sqlite.org/download.html) | [npm lib](https://www.npmjs.com/package/sqlite3)) for simple, secure, and speedy data storage. you can easily swap this out with the database of your choice.

for secrets, this server uses [dotenv](https://github.com/motdotla/dotenv) for storing and retrieving them. it is never a good idea to place secrets directly in your code.

## API Endpoints

- `/api/register` => POST handler for user registration requests.
- `/api/login` => POST handler for login requests.
- `/api/rftkn` => POST handler for refreshing access tokens given a valid refresh token. the expected header is `X-REF-TOK`.
- `/api/postmap` => POST request for updating map data.
- `/api/getmap` => GET request for retrieving map data.
- `/api/activate` => GET handler for user account activation via token and email.
- `/api/logout` => GET handler for logout requests. will disable the client token used to make the request.

## Databases used

- `campus_maps_users.db` => SQLite database for storing user credentials.
- `tkn_denylist.db` => SQLite database for denylisting (force expiring) tokens
- `map_layout.db` => SQLite database for map data storage

## Environment variables configured for this repo: 

- `at_exp` => access token expiration time in minutes
- `rt_exp` => refresh token expiration time in minutes
- `atpk` => access token private key
- `atpbk` => access token public key
- `rtpk` => refresh token private key
- `rtpbk` => refresh token public key
- `userdb_file` => path to `campus_maps_users.db`
- `mapdb_file` => path to `map_layout.db`
- `token_denylistdb_file` => path to `tkn_denylist.db`
