import { Request, Response } from "express";
import OauthClient, { IOauthClient } from "../models/OauthClient";
import HttpStatus from "../../../common/HttpStatus";
import crypto from "crypto";
import { v4 as uuidV4 } from "uuid";
import { serializeError } from "serialize-error";
import { linearizeErrors } from "@noreajs/mongoose";
import OauthDefaults, { IOauthDefaults } from "../OauthDefaults";

class OauthClientController {
  oauthParams: IOauthDefaults;

  constructor() {
    this.oauthParams = OauthDefaults;
  }
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
  create = async (req: Request, res: Response) => {
    try {
      // client id
      const clientId = uuidV4();
      // create a new oauth client
      const client = new OauthClient({
        clientId: clientId,
        name: req.body.name,
        website: req.body.website,
        logo: req.body.logo,
        programmingLanguage: req.body.programmingLanguage,
        scope: req.body.scope,
        legalTermsAcceptedAt: req.body.legalTermsAcceptedAt,
        clientProfile: req.body.clientProfile,
        secretKey: crypto
          .createHmac(
            this.oauthParams.OAUTH_HMAC_ALGORITHM,
            this.oauthParams.OAUTH_SECRET_KEY
          )
          .update(clientId)
          .digest("hex"),
        redirectURIs: req.body.redirectURIs,
      } as Partial<IOauthClient>);

      // save change
      await client.save();

      return res.status(HttpStatus.Created).json(client);
    } catch (e) {
      linearizeErrors(e);
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  };

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
          name: req.body.name || client.name,
          website: req.body.website || client.website,
          logo: req.body.logo || client.logo,
          programmingLanguage:
            req.body.programmingLanguage || client.programmingLanguage,
          scope: req.body.scope,
          legalTermsAcceptedAt:
            req.body.legalTermsAcceptedAt || client.legalTermsAcceptedAt,
          clientProfile: req.body.clientProfile || client.clientProfile,
          redirectURIs: req.body.redirectURIs || client.redirectURIs,
        } as Partial<IOauthClient>);
        // change approval state
        if (req.body.revoked !== undefined) {
          client.set({
            revokedAt: req.body.revoked ? new Date() : undefined,
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
