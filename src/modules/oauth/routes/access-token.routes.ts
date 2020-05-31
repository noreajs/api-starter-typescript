import { NoreaRouter } from "@noreajs/core";
import accessTokenController from "../controllers/access-token.controller";
import { IRequiredOauthContext } from "../OauthContext";

export default (module: NoreaRouter, oauthContext: IRequiredOauthContext) => {
  /**
   * Get token
   */
  module.route("/token").post([new accessTokenController(oauthContext).token]);

  /**
   * Get token info
   */
  module
    .route("/tokeninfo")
    .post([new accessTokenController(oauthContext).inspect]);

  /**
   * Get user info
   */
  module
    .route("/userinfo")
    .post([new accessTokenController(oauthContext).inspect]);

  /**
   * Purge revoked and expired token
   */
  module
    .route("/token/purge")
    .post([new accessTokenController(oauthContext).purge]);
};