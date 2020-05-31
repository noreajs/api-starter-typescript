import { Application } from "express";
import {
  IOauthContext,
  defaultOauthContext,
  IRequiredOauthContext,
} from "./OauthContext";
import oauthRoutes from "./routes/oauth.routes";

class Oauth {
  app: Application;

  constructor(app: Application) {
    this.app = app;
  }

  /**
   * Initialize oauth 2 module
   * @param context oauth 2 context
   */
  init(initContext: IOauthContext) {
    // create context
    const context: IRequiredOauthContext = {
      accessTokenExpiresIn:
        initContext.accessTokenExpiresIn ??
        defaultOauthContext.accessTokenExpiresIn,
      authenticationLogic: initContext.authenticationLogic,
      authorizationCodeLifeTime:
        initContext.authorizationCodeLifeTime ??
        defaultOauthContext.authorizationCodeLifeTime,
      jwtAlgorithm:
        initContext.jwtAlgorithm ?? defaultOauthContext.jwtAlgorithm,
      providerName: initContext.providerName,
      refreshTokenExpiresIn:
        initContext.refreshTokenExpiresIn ??
        defaultOauthContext.refreshTokenExpiresIn,
      secretKey: initContext.secretKey,
      tokenType: initContext.tokenType ?? defaultOauthContext.tokenType,
    };

    // Add oauth routes
    oauthRoutes(this.app, context);
  }
}

export default Oauth;
