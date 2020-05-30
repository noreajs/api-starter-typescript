import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import { IOauthDefaults } from "../OauthDefaults";
import IToken from "../interfaces/IToken";
import HttpStatus from "../../../common/HttpStatus";
import { Request, Response } from "express";
import IOauthError from "../interfaces/IOauthError";
import UtilsHelper from "./UtilsHelper";
import OauthHelper from "./OauthHelper";

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
       * Required parameters
       * *********************************
       */
      const requiredParameters = UtilsHelper.checkAttributes<ITokenRequest>(
        ["username", "password"],
        data
      );

      if (requiredParameters.length != 0) {
        return OauthHelper.throwError(res, {
          error: "invalid_request",
          error_description: `${requiredParameters.join(", ")} ${
            requiredParameters.length > 1 ? "are required" : "is required"
          }`,
        });
      }

      /**
       * Password Grant authentification data
       */
      const passwordGrantData = await oauthParams.authenticationLogic(
        data.username,
        data.password,
        data.scope
      );

      if (!passwordGrantData) {
        return OauthHelper.throwError(res, {
          error: "invalid_grant",
          error_description: `Given credentials are not valid or do not match any record.`,
        });
      }

      /**
       * Check scopes
       * ****************
       */
      const mergedScope = client.mergedScope(
        passwordGrantData.scope,
        data.scope
      );
      if (!mergedScope) {
        return OauthHelper.throwError(res, {
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
        oauthParams: oauthParams,
        grant: "password",
        scope: mergedScope,
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
      console.log(error);
      return OauthHelper.throwError(res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      });
    }
  }
}

export default TokenGrantPasswordCredentialsHelper;
