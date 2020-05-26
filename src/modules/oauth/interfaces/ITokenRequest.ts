export default interface ITokenRequest {
  grant_type: "authorization_code" | "password" | "client_credentials" | "refresh_token";
  refresh_token: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  code: string;
  code_verifier: string;
  username: string;
  password: string;
}

export const TokenRequestAttributes = {
  GRANT_TYPE: 'grant_type',
  REFRESH_TOKEN: 'refresh_token',
  CLIENT_ID: 'client_id',
  CLIENT_SECRET: 'client_secret',
  REDIRECT_URI: 'redirect_uri',
  CODE: 'code',
  CODE_VERIFIER: 'code_verifier',
  USERNAME: 'username',
  PASSWORD: 'password'
}