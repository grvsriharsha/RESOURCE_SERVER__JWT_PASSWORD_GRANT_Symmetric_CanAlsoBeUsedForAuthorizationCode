
create table oauth_access_token (
  token_id VARCHAR(2048),
  token VARBINARY(MAX),
  authentication_id VARCHAR(2048) PRIMARY KEY,
  user_name VARCHAR(2048),
  client_id VARCHAR(2048),
  authentication VARBINARY(MAX),
  refresh_token VARCHAR(2048)
);

create table oauth_refresh_token (
  token_id VARCHAR(2048),
  token VARBINARY(MAX),
  authentication VARBINARY(MAX)
);

select * from oauth_access_token;

select * from oauth_refresh_token;