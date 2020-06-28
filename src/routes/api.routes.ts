import { Request, Response } from "express";
import authRoutes from "./auth.routes";
import userRoutes from "./user.routes";
import { AppRoutes } from "@noreajs/core";

export default new AppRoutes({
  routes(app): void {
    /**
     * Api home
     */
    app.get("/", async (request: Request, response: Response) => {
      // response
      response.send({
        title: "Norea.js api starter project",
        description: "Oauth v2, user management, session, realtime",
        contact: {
          name: "Squirrel",
          email: "..."
        }
      });
    });

    app.post("/csp-report-violation", (req, res) => {
      if (req.body) {
        console.log("CSP Violation: ", req.body);
      } else {
        console.log("CSP Violation: No data received!");
      }

      res.status(204).end();
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
  middlewares(app): void {}
});
