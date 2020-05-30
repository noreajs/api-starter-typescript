import { NoreaRouter } from "@noreajs/core";
import oauthClientController from "../controllers/oauth-client.controller";

export default (module: NoreaRouter) => {
  /**
   * Oauth clients routes
   * *********************************
   */

  /**
   * Get all clients
   */
  module.route("/clients").get([oauthClientController.all]);

  /**
   * Create client
   */
  module.route("/clients").post([oauthClientController.create]);

  /**
   * Show client
   */
  module.route("/clients/:id").get([oauthClientController.show]);

  /**
   * Edit client
   */
  module.route("/clients/:id").put([oauthClientController.edit]);

  /**
   * Delete client
   */
  module.route("/clients/:id").delete([oauthClientController.delete]);
};
