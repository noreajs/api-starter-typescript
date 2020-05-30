import authorizationController from "../controllers/authorization.controller";
import oauthMiddleware from "../middlewares/oauth.middleware";
import { NoreaRouter } from "@noreajs/core";

export default (module: NoreaRouter) => {
  /**
   * Get authorization dialog
   */
  module.route("/dialog").get([authorizationController.dialog]);

  /**
   * Authorize
   */
  module
    .route("/authorize")
    .get([
      oauthMiddleware.validAuthorizationRequestRequired,
      authorizationController.authorize,
    ]);

  /**
   * Authenticate the user
   */
  module.route("/authorize").post([authorizationController.authenticate]);
};
