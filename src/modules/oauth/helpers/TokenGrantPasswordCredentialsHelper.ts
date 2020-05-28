import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import { IOauthDefaults } from "../OauthDefaults";
import IToken from "../interfaces/IToken";
import HttpStatus from "../../../common/HttpStatus";
import { Request, Response, request } from "express";
import ITokenError from "../interfaces/ITokenError";
import UtilsHelper from "./UtilsHelper";

class TokenGrantPasswordCredentialsHelper {
  /**
   * Resource Owner Password Credentials
   *
   * @param req request
   * @param res response
   * @param data token request data
   * @param client oauth client
   * @param oauthParams oauth params
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
      if (!client.validateScope(data.scope)) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_scope",
            error_description: "The request scope must be in client scope.",
          } as ITokenError,
        };
      }

      // Required parameters
      const requiredParameters = UtilsHelper.checkAttributes<ITokenRequest>(["username", "password"], data);

      if (requiredParameters.length != 0) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description: `${requiredParameters.join(", ")} ${
              requiredParameters.length > 1 ? "are required" : "is required"
            }`,
          } as ITokenError,
        };
      }

      /**
       * Password Grant authentification data
       */
      const passwordGrantData = await oauthParams.passwordCredentialsGrantAuthLogic(
        data.username,
        data.password,
        data.scope
      );

      if (!passwordGrantData) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_grant",
            error_description: `Given credentials are not valid or do not match any record.`,
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
        grant: "password",
        scope: passwordGrantData.scope,
        subject: passwordGrantData.userId,
      });

      return res.status(HttpStatus.Ok).json({
        access_token: tokens.token,
        token_type: oauthParams.OAUTH_TOKEN_TYPE,
        expires_in: tokens.accessTokenExpireIn,
        refresh_token: tokens.refreshToken,
        data: passwordGrantData.extraData,
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

export default TokenGrantPasswordCredentialsHelper;
