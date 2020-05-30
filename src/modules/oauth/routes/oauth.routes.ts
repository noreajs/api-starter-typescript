import { Application } from "express";
import { group } from "@noreajs/core";
import oauthController from "../controllers/oauth.controller";
import oauthClientRoutes from "./oauth-client.routes";
import authorizationRoutes from "./authorization.routes";
import accessTokenRoutes from "./access-token.routes";

export default (app: Application) => {

  /**
   * Auth routes
   */
  app.use(
    "/oauth",
    group([], (g) => {
      /**
       * Clients routes
       */
      oauthClientRoutes(g);

      /**
       * Authorization routes
       */
      authorizationRoutes(g);
      
      /**
       * Access tokens routes
       */
      accessTokenRoutes(g);

      /**
       * Get token
       */
      g.route("/callback").get([oauthController.callback]);
    })
  );
};
