export default interface IAuthCodeRequest {
  client_id: string;
  redirect_uri: string;
  response_type: "code" | "token";
  scope: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
}
