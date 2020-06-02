import { Application } from "express";
import { Route } from "@noreajs/core";
import oauthController from "../controllers/oauth.controller";
import oauthClientRoutes from "./oauth-client.routes";
import authorizationRoutes from "./authorization.routes";
import accessTokenRoutes from "./access-token.routes";
import OauthContext from "../OauthContext";

export default (app: Application, oauthContext: OauthContext) => {
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
        oauthClientRoutes(module, oauthContext);

        /**
         * Authorization routes
         */
        authorizationRoutes(module, oauthContext);

        /**
         * Access tokens routes
         */
        accessTokenRoutes(module, oauthContext);

        /**
         * Get token
         * For test purpose
         */
        module
          .route("/callback")
          .get([new oauthController(oauthContext).callback]);
      },
    })
  );
};
