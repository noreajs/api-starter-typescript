import { Request, Response, NextFunction } from "express";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import UtilsHelper from "../helpers/UtilsHelper";
import HttpStatus from "../../../common/HttpStatus";
import IAuthorizationErrorResponse from "../interfaces/IAuthorizationErrorResponse";
import OauthClient from "../models/OauthClient";
import ITokenError from "../interfaces/ITokenError";
import UrlHelper from "../helpers/UrlHelper";

class OauthMiddleware {
  /**
   * Authorization request validation required
   * @param req request
   * @param res response
   * @param next next function
   */
  async validAuthorizationRequestRequired(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    // get request query data
    let data: IAuthCodeRequest = req.query as IAuthCodeRequest;

    try {
      /**
       * Required parameters
       */
      const requiredParameters = UtilsHelper.checkAttributes<IAuthCodeRequest>(
        ["response_type", "redirect_uri", "client_id"],
        data
      );

      if (requiredParameters.length != 0) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description: `${requiredParameters.join(", ")} ${
              requiredParameters.length > 1 ? "are required" : "is required"
            }`,
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Code challenge method validation
       */
      if (
        data.code_challenge_method &&
        !["plain", "S256"].includes(data.code_challenge_method)
      ) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_request",
            error_description: `The code challenge method must be "plain" or "S256"`,
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Authentificate client
       * ***************************************
       */
      const client = await OauthClient.findOne({ clientId: data.client_id });

      /**
       * Client has to exist
       */
      if (!client) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description: "Unknown client",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      // Client revoked
      if (client.revokedAt) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "access_denied",
            error_description:
              "The client related to this request has been revoked.",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      if (!client.redirectURIs.includes(data.redirect_uri)) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description:
              "Given redirect uri is not in the client redirect URIs",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Check scopes
       * ****************
       */
      if (data.scope && !client.validateScope(data.scope)) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_scope",
            error_description: "The request scope must be in client scopes.",
          } as ITokenError,
        };
      }

      /**
       * Response type
       * ***************************
       */
      if (!["code", "token"].includes(data.response_type)) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "unsupported_response_type",
            error_description:
              "Expected value for response_type are 'token' and 'code'",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Inject data in request
       */
      res.locals.data = data;
      res.locals.client = client;
      
      // continue the request
      next();
    } catch (e) {
      if (e.status) {
        if (e.redirect !== false) {
          return res.redirect(
            UrlHelper.injectQueryParams(data.redirect_uri, e.data)
          );
        } else {
          return res.status(e.status).json(e.data);
        }
      } else {
        console.log(e);
        return res.status(HttpStatus.BadRequest).json({
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
          state: data.state,
        } as IAuthorizationErrorResponse);
      }
    }
  }
}

export default new OauthMiddleware();
