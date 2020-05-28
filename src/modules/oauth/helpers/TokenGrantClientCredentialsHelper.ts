import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import { IOauthDefaults } from "../OauthDefaults";
import IToken from "../interfaces/IToken";
import { Request, Response } from "express";
import moment from "moment";
import jwt from "jsonwebtoken";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import HttpStatus from "../../../common/HttpStatus";
import ITokenError from "../interfaces/ITokenError";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
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
       * Check client type
       */
      if (client.clientType !== "confidential") {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "unauthorized_client",
            error_description:
              "The authenticated client is not authorized to use this authorization grant type.",
          } as ITokenError,
        };
      }

      /**
       * Generate tokens
       * ******************************
       */
      const tokens = await client.newAccessToken({
        req: req,
        oauthParams: oauthParams,
        grant: "client_credentials",
        scope: data.scope,
        subject: client.clientId,
      });

      return res.status(HttpStatus.Ok).json({
        access_token: tokens.token,
        token_type: oauthParams.OAUTH_TOKEN_TYPE,
        expires_in: tokens.accessTokenExpireIn,
      } as IToken);
    } catch (error) {
      if (error.status) {
        return res.status(error.status).json(error.data);
      } else {
        console.log(error);
        return res.status(HttpStatus.BadRequest).json({
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        } as ITokenError);
      }
    }
  }
}

export default TokenGrantClientCredentialsHelper;
