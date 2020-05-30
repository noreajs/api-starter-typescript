import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import { IOauthDefaults } from "../OauthDefaults";
import IToken from "../interfaces/IToken";
import { Request, Response } from "express";
import HttpStatus from "../../../common/HttpStatus";
import IOauthError from "../interfaces/IOauthError";
import OauthHelper from "./OauthHelper";

class TokenGrantClientCredentialsHelper {
  /**
   * Client Credentials Grant
   *
   * @param req express request
   * @param res response
   * @param data token request
   * @param client oauth client
   * @param oauthParams oauth parameters
   */
  static async run(
    req: Request,
    res: Response,
    data: ITokenRequest,
    client: IOauthClient,
    oauthParams: IOauthDefaults
  ) {
    try {
      /**
       * Check scopes
       * ****************
       */
      const mergedScope = client.mergedScope(client.scope, data.scope);
      if (!mergedScope) {
        return OauthHelper.throwError(res, {
          error: "invalid_scope",
          error_description:
            "The requested scope is invalid, unknown, malformed, or exceeds the scope granted.",
        });
      }

      /**
       * Check client type
       */
      if (client.clientType !== "confidential") {
        return OauthHelper.throwError(res, {
          error: "unauthorized_client",
          error_description:
            "The authenticated client is not authorized to use this authorization grant type.",
        });
      }

      /**
       * Generate tokens
       * ******************************
       */
      const tokens = await client.newAccessToken({
        req: req,
        oauthParams: oauthParams,
        grant: "client_credentials",
        scope: mergedScope,
        subject: client.clientId,
      });

      return res.status(HttpStatus.Ok).json({
        access_token: tokens.token,
        token_type: oauthParams.OAUTH_TOKEN_TYPE,
        expires_in: tokens.accessTokenExpireIn,
      } as IToken);
    } catch (error) {
      console.log(error);
      return OauthHelper.throwError(res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      });
    }
  }
}

export default TokenGrantClientCredentialsHelper;
