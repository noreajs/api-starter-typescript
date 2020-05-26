import IOauthErrorType from "./IOauthErrorType";

export default interface ITokenError {
  error: IOauthErrorType;
  error_description: string;
  error_uri?: string;
}
