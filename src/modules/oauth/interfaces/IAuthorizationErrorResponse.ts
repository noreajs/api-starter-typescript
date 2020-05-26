import IOauthErrorType from "./IOauthErrorType";

export default interface IAuthorizationErrorResponse {
  error: IOauthErrorType;
  error_description: string;
  error_uri?: string;
  state?: string;
}
