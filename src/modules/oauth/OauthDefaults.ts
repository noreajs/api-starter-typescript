export interface IOauthDefaults {
  OAUTH_ISSUER: string;
  OAUTH_SECRET_KEY: string;
  OAUTH_EXPIRE_IN: number;
  OAUTH_AUTHORIZATION_CODE_LIFE_TIME: number;
  OAUTH_JWT_ALGORITHM:
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512";
  OAUTH_HMAC_ALGORITHM: string;
  passwordCredentialsGrantAuthLogic: (
    username: string,
    password: string
  ) => Promise<boolean> | boolean;
}

export default {
  OAUTH_ISSUER: "ISSUER",
  OAUTH_SECRET_KEY:
    "66a5ddac054bfe9389e82dea96c85c2084d4b011c3d33e0681a7488756a00ca334a1468015da8",
  OAUTH_EXPIRE_IN: 60 * 60 * 24,
  OAUTH_AUTHORIZATION_CODE_LIFE_TIME: 60 * 5,
  OAUTH_HMAC_ALGORITHM: "sha512",
  OAUTH_JWT_ALGORITHM: "HS512",
  passwordCredentialsGrantAuthLogic: () => true,
} as IOauthDefaults;
