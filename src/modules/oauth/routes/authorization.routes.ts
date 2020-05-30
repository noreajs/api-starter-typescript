import authorizationController from "../controllers/authorization.controller";
import { NoreaRouter } from "@noreajs/core";
import authorizationMiddleware from "../middlewares/authorization.middleware";

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
      authorizationMiddleware.validRequestRequired,
      authorizationController.authorize,
    ]);

  /**
   * Authenticate the user
   */
  module.route("/authorize").post([authorizationController.authenticate]);
};
