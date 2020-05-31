import IEndUserAuthData from "./interfaces/IEndUserAuthData";

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
  tokenType?: "Bearer";
  authenticationLogic: (
    username: string,
    password: string,
    scope?: string
  ) => Promise<IEndUserAuthData | undefined> | IEndUserAuthData | undefined;
  authorizationCodeLifeTime?: number;
  accessTokenExpiresIn?: OauthExpiresInType;
  refreshTokenExpiresIn?: OauthExpiresInType;
}

export type IRequiredOauthContext = Required<IOauthContext>;

export const defaultOauthContext: Required<Omit<
  IOauthContext,
  "providerName" | "secretKey"
>> = {
  jwtAlgorithm: "HS512",
  tokenType: "Bearer",
  authenticationLogic: function (
    username: string,
    password: string,
    scope?: string
  ) {
    return undefined;
  },
  authorizationCodeLifeTime: 60 * 5,
  accessTokenExpiresIn: {
    confidential: {
      internal: 60 * 60 * 24, // 24h
      external: 60 * 60 * 12, // 12h
    },
    public: {
      internal: 60 * 60 * 2, // 2h
      external: 60 * 60, // 1h
    },
  },
  refreshTokenExpiresIn: {
    confidential: {
      internal: 60 * 60 * 24 * 30 * 12, // 1 year
      external: 60 * 60 * 24 * 30, // 30 days
    },
    public: {
      internal: 60 * 60 * 24 * 30, // 30 days
      external: 60 * 60 * 24 * 7, // 1 week
    },
  },
};
