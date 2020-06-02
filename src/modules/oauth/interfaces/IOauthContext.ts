import IEndUserAuthData from "./IEndUserAuthData";
import { JwtTokenReservedClaimsType } from "./IJwt";

export type OauthExpiresInType = {
  confidential: {
    internal: number;
    external: number;
  };
  public: {
    internal: number;
    external: number;
  };
};

export interface IOauthContext {
  providerName: string;
  secretKey: string;
  jwtAlgorithm?:
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512";
    authenticationLogic: (
      username: string,
      password: string
    ) => Promise<IEndUserAuthData | undefined> | IEndUserAuthData | undefined;
    supportedOpenIdStandardClaims: (
      userId: string
    ) =>
      | Promise<JwtTokenReservedClaimsType | undefined>
      | JwtTokenReservedClaimsType
      | undefined;
  rsaKeysFolderPath?: string;
  tokenType?: "Bearer";
  authorizationCodeLifeTime?: number;
  accessTokenExpiresIn?: OauthExpiresInType;
  refreshTokenExpiresIn?: OauthExpiresInType;
}