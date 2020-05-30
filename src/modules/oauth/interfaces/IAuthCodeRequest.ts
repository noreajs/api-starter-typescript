export type IAuthorizationResponseType = "code" | "token";
export type ICodeChallengeMethodType = "plain" | "S256"

export default interface IAuthCodeRequest {
  client_id: string;
  redirect_uri: string;
  response_type: IAuthorizationResponseType;
  scope?: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: ICodeChallengeMethodType;
}
