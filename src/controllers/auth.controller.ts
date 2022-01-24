import { Request, Response } from "express";
import mongoose from "mongoose";
import User from "../models/User";
import { serializeError } from "serialize-error";
import IUser from "../interfaces/IUser";
import userProvider from "../providers/user.provider";
import { isFilled, isLocaleValid } from "@noreajs/common";
import { HttpStatus } from "@noreajs/core";

class AuthController {
  /**
   * Register a user
   * @param request request
   * @param response response
   */
  async register(request: Request, response: Response) {
    try {
      let user = new User({
        username: request.body.username,
        email: request.body.email,
        locale: request.headers["accept-language"],
      } as Partial<IUser>);

      // set secret code
      user.setPassword(request.body.password);

      await user.save();

      return response
        .status(HttpStatus.Created)
        .send((await userProvider.loadFullUser({ _id: user._id })) as IUser);
    } catch (error) {
      return response
        .status(HttpStatus.InternalServerError)
        .json(serializeError(error));
    }
  }

  /**
   * Update secret code
   * @param req request
   * @param res response
   */
  async updatePassword(req: Request, res: Response) {
    try {
      // load user
      const user: IUser = res.locals.user;
      // set changes
      user.setPassword(req.body.newPassword);
      // save changes
      await user.save();

      return res.status(HttpStatus.Ok).json(user);
    } catch (error) {
      return res
        .status(HttpStatus.InternalServerError)
        .json(serializeError(error));
    }
  }

  /**
   * Update secret code
   * @param req request
   * @param res response
   */
  async updateLocale(req: Request, res: Response) {
    try {
      // check locale validity
      if (!isFilled(req.body.locale)) {
        throw {
          status: HttpStatus.BadRequest,
          message: "The locale is required",
        };
      } else if (!isLocaleValid(req.body.locale)) {
        throw {
          status: HttpStatus.BadRequest,
          message: `The format of the given locale (${req.body.locale}) is not correct. Expected example: en-US, fr-FR`,
        };
      }
      // load user
      const user: IUser = res.locals.user;
      // set changes
      user.set({
        locale: req.body.locale,
      } as Partial<IUser>);
      // save changes
      await user.save();

      return res.status(HttpStatus.Ok).json(user);
    } catch (error) {
      return res
        .status(HttpStatus.InternalServerError)
        .json(serializeError(error));
    }
  }

  /**
   * Update account (phone number and username only)
   * @param req request
   * @param res response
   */
  async updateAccount(req: Request, res: Response) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // load user
      const user: IUser = res.locals.user;
      // last phone number
      const lastEmail = user.email;
      // set changes
      user.set({
        username: req.body.username || user.username,
        email: req.body.email || user.email,
      } as IUser);
      // save changes
      await user.save({ session });

      /**
       * If the phone number changed
       */
      if (lastEmail !== user.email) {
        // delete verification state
        user.emailVerifiedAt = undefined;
        // save changes
        await user.save({ session });
      }

      await session.commitTransaction();
      session.endSession();

      return res.status(HttpStatus.Ok).json(user);
    } catch (error) {
      await session.abortTransaction();
      session.endSession();

      return res
        .status(HttpStatus.InternalServerError)
        .json(serializeError(error));
    }
  }

  /**
   * Reset the secret code of the given phone number
   * @param req request
   * @param res response
   */
  async resetPassword(req: Request, res: Response) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // load user
      const user = await userProvider.loadFullUser(
        { email: req.body.email },
        session
      );

      if (user) {
        //
        // your code here
        //

        await session.commitTransaction();
        session.endSession();

        return res.status(HttpStatus.Ok).send();
      } else {
        throw {
          status: HttpStatus.NotFound,
          message: "There is not account related to this number.",
        };
      }
    } catch (error) {
      await session.abortTransaction();
      session.endSession();

      return res
        .status((error as any).status || HttpStatus.InternalServerError)
        .json(serializeError(error));
    }
  }
}

export default new AuthController();
