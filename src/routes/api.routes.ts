import { Request, Response } from "express";
import authRoutes from "./auth.routes";
import userRoutes from "./user.routes";
import { AppRoutes } from "@noreajs/core";
import userNotification from "../notifications/user.notification";

export default new AppRoutes({
  routes(app): void {
    /**
     * Api home
     */
    app.get("/",  async (request: Request, response: Response) => {
      // hello
      await userNotification.sms("userDeleted", "Arnold");
      
      // response
      response.send({
        title: "Ocnode Api initial project",
        description: "Initial api based on ocnode framework",
        contact: {
          name: "OvniCode Team",
          email: "team@ovnicode.com",
        },
      });
    });

    /**
     * Auth routes
     */
    authRoutes(app);

    /**
     * Users routes
     */
    userRoutes(app);
  },
  middlewares(app): void {},
});
