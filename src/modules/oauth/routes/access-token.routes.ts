import { NoreaRouter } from "@noreajs/core";
import accessTokenController from "../controllers/access-token.controller";

export default (module: NoreaRouter) => {
    /**
       * Get token
       */
      module.route("/token").post([accessTokenController.token]);

      /**
       * Get token info
       */
      module.route("/tokeninfo").post([accessTokenController.inspect]);

      /**
       * Get user info
       */
      module.route("/userinfo").post([accessTokenController.inspect]);

      /**
       * Purge revoked and expired token
       */
      module.route("/token/purge").post([accessTokenController.purge]);
};