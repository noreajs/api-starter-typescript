import authMiddleware from "../middlewares/auth.middleware";
import userController from "../controllers/user.controller";
import { Oauth } from "@noreajs/oauth-v2-provider-me";
import { NoreaApplication } from "@noreajs/core";

export default (app: NoreaApplication) => {
  /**
   * Get online users count
   */
  app.route("/realtime/count/online-users").get(userController.onlineUsers);

  /**
   * Get connected users count
   */
  app
    .route("/realtime/count/connected-users")
    .get(userController.connectedUsers);

  /**
   * Get user lists
   */
  app
    .route("/users")
    .get([Oauth.authorize(), authMiddleware.adminOnly, userController.all]);

  /**
   * update user lock state (locked or unlocked)
   */
  app
    .route("/users/:id/lock-state")
    .put([
      Oauth.authorize(),
      authMiddleware.adminOnly,
      userController.editLockedState,
    ]);

  /**
   * Show user
   */
  app
    .route("/users/:id")
    .get([Oauth.authorize(), authMiddleware.adminOnly, userController.show]);

  /**
   * Edit user
   */
  app.route("/users/:id").put([
    Oauth.authorize(),
    authMiddleware.adminOnly,
    // userController.edit
  ]);

  /**
   * Get the current user details
   */
  app
    .route("/current-user")
    .get([Oauth.authorize(), userController.currentUser]);

  /**
   * Delete user account
   */
  app.route("/users/:id").delete([Oauth.authorize(), userController.delete]);
};
