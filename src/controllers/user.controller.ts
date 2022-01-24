import mongoose from "mongoose";
import { serializeError } from "serialize-error";
import IUser from "../interfaces/IUser";
import { isQueryParamFilled } from "@noreajs/common";
import { HttpStatus, Validator } from "@noreajs/core";
import { Response, Request } from "express";
import { v1 as uuidv1 } from "uuid";
import User from "../models/User";
import userProvider from "../providers/user.provider";
import { Server } from "socket.io";

/**
 * Manage user
 */
class UserController {
  /**
   * Get all users
   * @param req request
   * @param res response
   */
  async all(req: Request, res: Response) {
    //query data
    const queryData: any[string] = [];

    // username
    if (isQueryParamFilled(req.query.username)) {
      queryData["username"] = { $regex: `.*${req.query.username}.*` };
    }

    await User.paginate(
      { ...queryData },
      {
        page: parseInt((req.query.page ?? 1) as any),
        limit: parseInt((req.query.limit ?? 20) as any),
        sort: { createdAt: "desc" },
      }
    )
      .then(function (data) {
        res.status(HttpStatus.Ok).json(data);
      })
      .catch(function (err) {
        res.status(HttpStatus.InternalServerError).json(serializeError(err));
      });
  }

  /**
   * Edit user locked state
   * @param req request
   * @param res response
   */
  async editLockedState(req: Request, res: Response) {
    try {
      // load user
      const user = await User.findById(req.params.id);

      if (user) {
        /**
         * Check if locked param exist in request body
         */
        const validation = await Validator.validate(req, "body", {
          locked: {
            type: "bool",
            required: true,
          },
        });

        // validation fails
        if (validation.errors.length !== 0) {
          throw validation;
        }

        // update state
        user.lockedAt = req.body.locked ? new Date() : undefined;

        //save changes
        await user.save();

        return res.status(HttpStatus.Ok).send();
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }

  /**
   * Get online users count
   *
   * @param req request
   * @param res response
   */
  async onlineUsers(req: Request, res: Response) {
    try {
      const socketServer: Server = res.locals.socketServer;

      // send the result to the
      res.status(HttpStatus.Ok).json({
        count: await socketServer.allSockets(),
      });
    } catch (error) {
      res.status(HttpStatus.InternalServerError).json(error);
    }
  }

  /**
   * Get connected users count
   *
   * @param req request
   * @param res response
   */
  async connectedUsers(req: Request, res: Response) {
    const onlineUsersCount = await User.countDocuments({ online: true });
    res.status(HttpStatus.Ok).json({
      count: onlineUsersCount,
    });
  }

  /**
   * Get user details
   *
   * @param req request
   * @param res response
   */
  async show(req: Request, res: Response) {
    try {
      // load user
      const user = await userProvider.loadFullUser({ _id: req.params.id });
      if (user) {
        res.status(HttpStatus.Ok).json(user);
      } else {
        res.status(HttpStatus.NotFound).json();
      }
    } catch (error) {
      res.status(HttpStatus.InternalServerError).json(serializeError(error));
    }
  }

  /**
   * Get the current user details
   *
   * @param req request
   * @param res response
   */
  async currentUser(req: Request, res: Response) {
    try {
      // load user
      const user = await userProvider.loadFullUser({
        _id: res.locals.user._id,
      });
      if (user) {
        res.status(HttpStatus.Ok).json(user);
      } else {
        res.status(HttpStatus.NotFound).json();
      }
    } catch (error) {
      res.status(HttpStatus.InternalServerError).json(serializeError(error));
    }
  }

  /**
   * Delete user account
   * @param req request
   * @param res response
   */
  async delete(req: Request, res: Response) {
    try {
      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        // update space
        await User.updateOne(
          { _id: res.locals.user._id },
          {
            username: `DELETED-${res.locals.user.username}-${uuidv1()}`,
            deletedAt: new Date(),
          } as Partial<IUser>,
          { runValidators: true }
        );

        return res.status(HttpStatus.Ok).send();
      } catch (e) {
        await session.abortTransaction();
        session.endSession();

        throw e;
      }
    } catch (error) {
      return res
        .status((error as any).status || 500)
        .json(serializeError(error));
    }
  }
}

export default new UserController() as UserController;
