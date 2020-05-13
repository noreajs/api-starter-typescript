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
