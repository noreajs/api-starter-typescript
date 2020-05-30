import { Application } from "express";
import { group } from "@noreajs/core";
import oauthController from "../controllers/oauth.controller";
import oauthClientController from "../controllers/oauth-client.controller";
import oauthMiddleware from "../middlewares/oauth.middleware";
import authorizationController from "../controllers/authorization.controller";

export default (app: Application) => {
  /**
   * Auth routes
   */
  app.use(
    "/oauth",
    group([], (g) => {
      /**
       * Get all clients
       */
      g.route("/clients").get([oauthClientController.all]);

      /**
       * Create client
       */
      g.route("/clients").post([oauthClientController.create]);

      /**
       * Show client
       */
      g.route("/clients/:id").get([oauthClientController.show]);

      /**
       * Edit client
       */
      g.route("/clients/:id").put([oauthClientController.edit]);

      /**
       * Delete client
       */
      g.route("/clients/:id").delete([oauthClientController.delete]);

      /**
       * Get authorization dialog
       */
      g.route("/dialog").get([oauthController.dialog]);

      /**
       * Authorize
       */
      g.route("/authorize").get([
        oauthMiddleware.validAuthorizationRequestRequired,
        authorizationController.authorize,
      ]);

      /**
       * Authenticate the user
       */
      g.route("/authorize").post([authorizationController.authenticate]);

      /**
       * Get token
       */
      g.route("/token").post([oauthController.token]);

      /**
       * Get token info
       */
      g.route("/tokeninfo").post([oauthController.inspect]);

      /**
       * Get user info
       */
      g.route("/userinfo").post([oauthController.inspect]);

      /**
       * Purge revoked and expired token
       */
      g.route("/token/purge").post([oauthController.purge]);

      /**
       * Get token
       */
      g.route("/callback").get([oauthController.callback]);
    })
  );
};
