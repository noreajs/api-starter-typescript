import { Request, Response } from "express";
import OauthClient, { IOauthClient } from "../models/OauthClient";
import HttpStatus from "../../../common/HttpStatus";
import crypto from "crypto";
import { serializeError } from "serialize-error";
import { linearizeErrors } from "../../../core/mongoose/MongooseUtilities";

class OauthClientController {
  /**
   * Get all clients
   * @param req request
   * @param res response
   */
  async all(req: Request, res: Response) {
    await OauthClient.paginate()
      .then((result) => {
        return res.status(HttpStatus.Ok).json(result);
      })
      .catch((e) => {
        return res
          .status(HttpStatus.InternalServerError)
          .json(serializeError(e));
      });
  }

  /**
   * Create a client
   * @param req request
   * @param res response
   */
  async create(req: Request, res: Response) {
    try {
      // secret
      const secretHash = crypto.createHash("sha256");
      // update code
      secretHash.update(crypto.randomBytes(50).toString("hex"), "utf8");
      // create a new oauth client
      const client = new OauthClient({
        name: req.body.name,
        secret: secretHash.digest("hex"),
        provider: "noreajs",
        redirect: req.body.redirect,
        personalAccessClient: req.body.personalAccessClient,
        passwordClient: req.body.passwordClient,
        revoked: false,
      } as Partial<IOauthClient>);

      // save change
      await client.save();

      return res.status(HttpStatus.Created).json(client);
    } catch (e) {
      linearizeErrors(e);
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }

  /**
   * Edit a client
   * @param req request
   * @param res response
   */
  async edit(req: Request, res: Response) {
    try {
      // load client
      const client = await OauthClient.findById(req.params.id);

      if (client) {
        // apply changes
        client.set({
          name: req.body.name,
          redirect: req.body.redirect || client.redirect,
          personalAccessClient:
            req.body.personalAccessClient != undefined
              ? req.body.personalAccessClient
              : client.personalAccessClient,
          passwordClient:
            req.body.passwordClient != undefined
              ? req.body.passwordClient
              : client.passwordClient,
        } as Partial<IOauthClient>);
        // change approval state
        if (req.body.approved !== undefined) {
          client.set({
            approvedAt: req.body.approved ? new Date() : undefined,
          });
        }
        // save changes
        await client.save();

        return res.status(HttpStatus.Ok).json(client);
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      linearizeErrors(e);
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }

  /**
   * Get client details
   * @param req request
   * @param res response
   */
  async show(req: Request, res: Response) {
    try {
      // load client
      const client = await OauthClient.findById(req.params.id);

      if (client) {
        return res.status(HttpStatus.Ok).json(client);
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }

  /**
   * Delete a client
   * @param req request
   * @param res response
   */
  async delete(req: Request, res: Response) {
    try {
      // load client
      const client = await OauthClient.findById(req.params.id);

      if (client) {
        // remove the client
        await client.remove();
        return res.status(HttpStatus.Ok).send();
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }
}

export default new OauthClientController();
