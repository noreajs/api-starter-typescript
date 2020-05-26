type IOauthErrorType =
  | "invalid_request"
  | "invalid_client"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "unsupported_grant_type"
  | "invalid_grant"
  | "temporarily_unavailable";

export default IOauthErrorType;
