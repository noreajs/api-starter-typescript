import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import IToken from "../interfaces/IToken";
import HttpStatus from "../../../common/HttpStatus";
import { Request, Response } from "express";
import UtilsHelper from "./UtilsHelper";
import OauthHelper from "./OauthHelper";
import OauthContext from "../OauthContext";

class TokenGrantPasswordCredentialsHelper {
  /**
   * Resource Owner Password Credentials
   *
   * @param req request
   * @param res response
   * @param data token request data
   * @param client oauth client
   * @param oauthContext oauth params
   */
  static async run(
    req: Request,
    res: Response,
    data: ITokenRequest,
    client: IOauthClient,
    oauthContext: OauthContext
  ) {
    try {
      /**
       * Required parameters
       * *********************************
       */
      const requiredParameters = UtilsHelper.checkAttributes<ITokenRequest>(
        ["username", "password"],
        data
      );

      if (requiredParameters.length != 0) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description: `${requiredParameters.join(", ")} ${
            requiredParameters.length > 1 ? "are required" : "is required"
          }`,
        });
      }

      /**
       * Password Grant authentification data
       */
      const endUserAuthData = await oauthContext.authenticationLogic(
        data.username,
        data.password
      );

      if (!endUserAuthData) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_grant",
          error_description: `Given credentials are not valid or do not match any record.`,
        });
      }

      /**
       * Check scopes
       * ****************
       */
      const mergedScope = client.mergedScope(
        endUserAuthData.scope,
        data.scope
      );
      if (!mergedScope) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_scope",
          error_description: "The request scope must be in client scope.",
        });
      }

      /**
       * Generate tokens
       * ******************************
       */
      const tokens = await client.newAccessToken({
        req: req,
        oauthContext: oauthContext,
        grant: "password",
        scope: mergedScope,
        subject: endUserAuthData.userId,
      });

      return res.status(HttpStatus.Ok).json({
        access_token: tokens.token,
        token_type: oauthContext.tokenType,
        expires_in: tokens.accessTokenExpireIn,
        refresh_token: tokens.refreshToken,
        data: endUserAuthData.extraData,
      } as IToken);
    } catch (error) {
      console.log(error);
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      });
    }
  }
}

export default TokenGrantPasswordCredentialsHelper;
