import IPasswordGrantAuthData from "./interfaces/IPasswordGrantAuthData";
import { v4 as uuidV4 } from "uuid";

export interface IOauthDefaults {
  OAUTH_ISSUER: string;
  OAUTH_SECRET_KEY: string;
  OAUTH_ACCESS_TOKEN_EXPIRE_IN: number;
  OAUTH_REFRESH_TOKEN_EXPIRE_IN: number;
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
  OAUTH_TOKEN_TYPE: "Bearer" | string;
  passwordCredentialsGrantAuthLogic: (
    username: string,
    password: string,
    scope?: string
  ) => Promise<IPasswordGrantAuthData> | IPasswordGrantAuthData;
}

export default {
  OAUTH_ISSUER: "ISSUER",
  OAUTH_SECRET_KEY:
    "66a5ddac054bfe9389e82dea96c85c2084d4b011c3d33e0681a7488756a00ca334a1468015da8",
  OAUTH_ACCESS_TOKEN_EXPIRE_IN: 60 * 60 * 24,
  OAUTH_REFRESH_TOKEN_EXPIRE_IN: 60 * 60 * 24 * 30 * 12,
  OAUTH_AUTHORIZATION_CODE_LIFE_TIME: 60 * 5,
  OAUTH_HMAC_ALGORITHM: "sha512",
  OAUTH_JWT_ALGORITHM: "HS512",
  OAUTH_TOKEN_TYPE: "Bearer",
  passwordCredentialsGrantAuthLogic: function (
    username: string,
    password: string,
    scope?: string
  ) {
    const userId = uuidV4();
    return {
      userId: userId,
      // scope: "*",
      extraData: {
        user: {
          id: userId,
          username: username,
          connectionDate: new Date(),
        },
      },
    };
  },
} as IOauthDefaults;
