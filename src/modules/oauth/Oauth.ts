import { Application } from "express";
import {
  IOauthContext,
} from "./interfaces/IOauthContext";
import oauthRoutes from "./routes/oauth.routes";
import UtilsHelper from "./helpers/UtilsHelper";
import OauthContext from "./OauthContext";

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
    // Add oauth routes
    oauthRoutes(this.app, new OauthContext(initContext));
  }
}

export default Oauth;
