import { NoreaRouter, Route } from "@noreajs/core";
import oauthClientController from "../controllers/oauth-client.controller";

export default (module: NoreaRouter) => {
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
        sub.route("/").get([oauthClientController.all]);

        /**
         * Create client
         */
        sub.route("/").post([oauthClientController.create]);

        /**
         * Show client
         */
        sub.route("/:clientId").get([oauthClientController.show]);

        /**
         * Edit client
         */
        sub.route("/:clientId").put([oauthClientController.edit]);

        /**
         * Delete client
         */
        sub.route("/:clientId").delete([oauthClientController.delete]);
      },
    })
  );
};
