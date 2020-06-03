import { Request, Response, NextFunction } from "express";
import { serializeError } from "serialize-error";
import { verify } from "unixcrypt";
import User from "../models/User";
import IUser from "../interfaces/IUser";
import { isFilled, HttpStatus } from "@noreajs/common";

class AuthMiddleware {
  /**
   * Only administrator can access to the resource
   *
   * @param req
   * @param res
   * @param next
   */
  adminOnly(req: Request, res: Response, next: NextFunction) {
    if (res.locals.user.admin) {
      return next();
    } else {
      return res.status(HttpStatus.Forbidden).send({
        message: "Admin only can access to this route.",
      });
    }
  }

  /**
   * Check the user credentials
   *
   * @param req
   * @param res
   * @param next
   */
  async isSecretCodeAndUserMatch(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    await User.findOne({
      email: req.body.email,
      $or: [{ deletedAt: { $exists: false } }],
    })
      .then((user: IUser | null) => {
        if (user) {
          if (verify(req.body.password, user.password)) {
            return next();
          } else {
            return res.status(HttpStatus.BadRequest).json({
              message: "Check your credentials",
            });
          }
        } else {
          return res.status(HttpStatus.BadRequest).json({
            message: `No account associated with the email ${req.body.email}`,
          });
        }
      })
      .catch((error: any) => {
        return res.status(HttpStatus.InternalServerError).json({
          message: `Internal problem. Contact support`,
          error: serializeError(error),
        });
      });
  }

  /**
   * Check user secret code in request
   * Always used after validJwtNeeded method
   *
   * @param req request
   * @param res response
   * @param next request chain
   */
  async passwordRequired(req: Request, res: Response, next: NextFunction) {
    // load user
    const user = res.locals.user;

    // secret code required
    if (!isFilled(req.body.password)) {
      return res.status(HttpStatus.BadRequest).json({
        message: "The secret code is required for this request.",
      });
    }
    // check the user secret code
    else if (verify(req.body.password, user.password)) {
      return next();
    } else {
      return res.status(HttpStatus.Forbidden).json({
        message: "The given secret code is not correct.",
      });
    }
  }

  /**
   * Check if the current user has a verified email
   * @param req request
   * @param res response
   * @param next request chain
   */
  async emailVerified(req: Request, res: Response, next: NextFunction) {
    if (!res.locals.user.emailVerifiedAt) {
      return res.status(403).json({
        message: "Verify your email before performing this action.",
      });
    } else {
      return next();
    }
  }
}

export default new AuthMiddleware() as AuthMiddleware;
