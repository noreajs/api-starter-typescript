import OauthContext from "../OauthContext";
import { NoreaRouter, Route } from "@noreajs/core";
import OauthScopeController from "../controllers/oauth-scope.controller";

export default (module: NoreaRouter, oauthContext: OauthContext) => {
    /**
   * Oauth scopes routes
   * *********************************
   */
  module.use(
    "/scopes",
    Route.group({
      routes: (sub) => {
        /**
         * Get all scopes
         */
        sub.route("/").get([new OauthScopeController(oauthContext).all]);

        /**
         * Create scope
         */
        sub.route("/").post([new OauthScopeController(oauthContext).create]);

        /**
         * Show scope
         */
        sub
          .route("/:scopeId")
          .get([new OauthScopeController(oauthContext).show]);

        /**
         * Edit scope
         */
        sub
          .route("/:scopeId")
          .put([new OauthScopeController(oauthContext).edit]);

        /**
         * Delete scope
         */
        sub
          .route("/:scopeId")
          .delete([new OauthScopeController(oauthContext).delete]);
      },
    })
  );
}