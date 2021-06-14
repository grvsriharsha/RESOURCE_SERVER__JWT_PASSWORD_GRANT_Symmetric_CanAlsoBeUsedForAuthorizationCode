# passwordGrant_JWTTokenstore_oauth

First run the sql files in sql folder,which now includes creating rule ,user,oauth_access_token,oauth_referesh_token so spring security can use this.
The Authorization and Resource Server is created.
The token generted for the user logged in  is now stored in Database.The Respurce server uses this token and extracts the username and token.
We are using PasswordGrant.The only difference is we are using JWTTokenstore instead of inmemory or jdbcTokenstore

The whle project is about to haveing 2 apis,get and post. 
There are 2 users one is admin,other is user.So the Roles are created for the users.

Now we configure the websecurity adapter so that
 1. Only Admins can use post
 2. Both Admins and users can use GET
 
 User Logs in with email and pasword
