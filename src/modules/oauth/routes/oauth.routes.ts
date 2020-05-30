import { Application } from "express";
import { Route } from "@noreajs/core";
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
    Route.group({
      routes: (module) => {
        /**
         * Clients routes
         */
        oauthClientRoutes(module);

        /**
         * Authorization routes
         */
        authorizationRoutes(module);

        /**
         * Access tokens routes
         */
        accessTokenRoutes(module);

        /**
         * Get token
         * For test purpose
         */
        module.route("/callback").get([oauthController.callback]);
      },
    })
  );
};
