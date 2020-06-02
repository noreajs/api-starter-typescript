import {
  OauthExpiresInType,
  IOauthContext,
} from "./interfaces/IOauthContext";
import { Request } from "express";
import UrlHelper from "./helpers/UrlHelper";
import UtilsHelper from "./helpers/UtilsHelper";
import IEndUserAuthData from "./interfaces/IEndUserAuthData";
import { JwtTokenReservedClaimsType } from "./interfaces/IJwt";

export default class OauthContext {
  providerName: string;
  secretKey: string;
  jwtAlgorithm:
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
  rsaKeysFolderPath: string;
  tokenType: "Bearer";
  authorizationCodeLifeTime: number;
  accessTokenExpiresIn: OauthExpiresInType;
  refreshTokenExpiresIn: OauthExpiresInType;
  rsaKeys: {
    publicKey: string;
    privateKey: string;
  };

  constructor(init: IOauthContext) {
    /**
     * Initialize context
     */
    this.accessTokenExpiresIn = init.accessTokenExpiresIn ?? {
      confidential: {
        internal: 60 * 60 * 24, // 24h
        external: 60 * 60 * 12, // 12h
      },
      public: {
        internal: 60 * 60 * 2, // 2h
        external: 60 * 60, // 1h
      },
    };
    this.authenticationLogic = init.authenticationLogic;
    this.supportedOpenIdStandardClaims = init.supportedOpenIdStandardClaims;
    this.authorizationCodeLifeTime = init.authorizationCodeLifeTime ?? 60 * 5;
    this.jwtAlgorithm = init.jwtAlgorithm ?? "HS512";
    this.providerName = init.providerName;
    this.refreshTokenExpiresIn = init.refreshTokenExpiresIn ?? {
      confidential: {
        internal: 60 * 60 * 24 * 30 * 12, // 1 year
        external: 60 * 60 * 24 * 30, // 30 days
      },
      public: {
        internal: 60 * 60 * 24 * 30, // 30 days
        external: 60 * 60 * 24 * 7, // 1 week
      },
    };
    this.rsaKeysFolderPath = init.rsaKeysFolderPath ?? "rsa-keys";
    this.secretKey = init.secretKey;
    this.tokenType = init.tokenType ?? "Bearer";
    // generate RSA Keys
    this.rsaKeys = UtilsHelper.generateRsaKeys(this.rsaKeysFolderPath);

  }
}