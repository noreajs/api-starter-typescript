import authorizationController from "../controllers/authorization.controller";
import { NoreaRouter } from "@noreajs/core";
import authorizationMiddleware from "../middlewares/authorization.middleware";
import OauthContext from "../OauthContext";

export default (module: NoreaRouter, oauthContext: OauthContext) => {
  /**
   * Get authorization dialog
   */
  module
    .route("/dialog")
    .get([new authorizationController(oauthContext).dialog]);

  /**
   * Authorize
   */
  module
    .route("/authorize")
    .get([
      authorizationMiddleware.validRequestRequired,
      new authorizationController(oauthContext).authorize,
    ]);

  /**
   * Authenticate the user
   */
  module
    .route("/authorize")
    .post([new authorizationController(oauthContext).authenticate]);
};