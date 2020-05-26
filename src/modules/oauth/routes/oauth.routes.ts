import { Application } from "express";
import { group } from "@noreajs/core";
import oauthController from "../controllers/oauth.controller";
import oauthClientController from "../controllers/oauth-client.controller";

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
       * Authorise
       */
      g.route("/authorize").get([oauthController.authorize]);

      /**
       * Get token
       */
      g.route("/token").post([oauthController.token]);

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
