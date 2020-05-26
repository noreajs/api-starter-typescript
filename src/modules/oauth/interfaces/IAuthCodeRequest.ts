export default interface IAuthCodeRequest {
  client_id: string;
  redirect_uri: string;
  response_type: "code" | "token";
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: "plain" | "S256";
}

// export const AuthCodeRequestAttributes = {
//   CLIENT_ID: "client_id",
//   REDIRECT_URI: "redirect_uri",
//   RESPONSE_TYPE: "response_type",
//   SCOPE: "scope",
//   STATE: "state",
//   CODE_CHALLENGE: "code_challenge",
//   CODE_CHALLENGE_METHOD: "code_challenge_method",
// };
