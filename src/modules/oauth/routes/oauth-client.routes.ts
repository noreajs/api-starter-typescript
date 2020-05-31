import { NoreaRouter, Route } from "@noreajs/core";
import oauthClientController from "../controllers/oauth-client.controller";
import { IRequiredOauthContext } from "../OauthContext";

export default (module: NoreaRouter, oauthContext: IRequiredOauthContext) => {
  /**
   * Oauth clients routes
   * *********************************
   */
  module.use(
    "/clients",
    Route.group({
      routes: (sub) => {
        /**
         * Get all clients
         */
        sub.route("/").get([new oauthClientController(oauthContext).all]);

        /**
         * Create client
         */
        sub.route("/").post([new oauthClientController(oauthContext).create]);

        /**
         * Show client
         */
        sub
          .route("/:clientId")
          .get([new oauthClientController(oauthContext).show]);

        /**
         * Edit client
         */
        sub
          .route("/:clientId")
          .put([new oauthClientController(oauthContext).edit]);

        /**
         * Delete client
         */
        sub
          .route("/:clientId")
          .delete([new oauthClientController(oauthContext).delete]);
      },
    })
  );
};
