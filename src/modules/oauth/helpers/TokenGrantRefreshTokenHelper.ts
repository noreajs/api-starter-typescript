import ITokenRequest from "../interfaces/ITokenRequest";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { IOauthClient } from "../models/OauthClient";
import HttpStatus from "../../../common/HttpStatus";
import OauthRefreshToken, {
  IOauthRefreshToken,
} from "../models/OauthRefreshToken";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import moment from "moment";
import IToken from "../interfaces/IToken";
import OauthHelper from "./OauthHelper";
import UtilsHelper from "./UtilsHelper";
import { IJwtTokenPayload } from "../interfaces/IJwt";
import OauthContext from "../OauthContext";

class TokenGrantRefreshTokenHelper {
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
       * Check scopes
       * ****************
       */
      if (!client.validateScope(data.scope)) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_scope",
          error_description: "The request scope must be in client scope.",
        });
      }

      /**
       * REFRESH TOKEN VERIFICATION
       * *******************************
       */

      // Check if refresh token is within the request
      if (
        UtilsHelper.checkAttributes<ITokenRequest>(["refresh_token"], data)
          .length !== 0
      ) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description: `refresh_token is required.`,
        });
      }

      /**
       * Get refresh token data
       * *******************************
       */
      try {
        // Verify token signature
        const refreshTokenData = jwt.verify(
          data.refresh_token,
          oauthContext.secretKey,
          {
            algorithms: [oauthContext.jwtAlgorithm],
          }
        ) as IJwtTokenPayload;

        // load refresh token
        const oauthRefreshToken = await OauthRefreshToken.findOne({
          _id: refreshTokenData.jti,
        });

        // refresh token doesn't exist
        if (!oauthRefreshToken) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description: `Unknown refresh token.`,
          });
        }

        // is related access token still active
        if (moment().isBefore(oauthRefreshToken.accessToken.expiresAt)) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description: `I access token associated with the refresh token is still active.`,
          });
        }

        // refresh token expired
        if (moment().isAfter(oauthRefreshToken.expiresAt)) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description: `The refresh token is expired.`,
          });
        }

        // refresh token revoked
        if (oauthRefreshToken.revokedAt) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description: `The refresh token is revoked.`,
          });
        }

        /**
         * Verify client_id
         * *******************************
         */
        if (data.client_id !== refreshTokenData.client_id) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description: `Invalid refresh token. client_id does not match.`,
          });
        }

        /**
         * Verify scope
         * *******************************
         */

        // new access token scope, identical with the previous by default
        let newAccessTokenScope = oauthRefreshToken.accessToken.scope;

        if (data.scope && newAccessTokenScope) {
          const currentScopes = newAccessTokenScope.split(" ");
          const newScopes = data.scope.split(" ");
          for (const scope of newScopes) {
            if (currentScopes.includes(scope)) {
              return OauthHelper.throwError(req, res, {
                error: "invalid_scope",
                error_description: `${scope} is already in the previous access token scope.`,
              });
            } else {
              currentScopes.push(scope);
            }
          }
          // update new access token scope
          newAccessTokenScope = currentScopes.join(" ");
        }

        /**
         * Revocation of the refresh token
         */
        await OauthRefreshToken.updateOne(
          {
            _id: oauthRefreshToken._id,
          },
          {
            revokedAt: new Date(),
          } as Partial<IOauthRefreshToken>
        );

        /**
         * Create JWT token
         * ******************************
         */
        const tokens = await client.newAccessToken({
          grant: "refresh_token",
          oauthContext: oauthContext,
          req: req,
          scope: newAccessTokenScope,
          subject: oauthRefreshToken.accessToken.userId,
        });

        return res.status(HttpStatus.Ok).json({
          access_token: tokens.token,
          token_type: oauthContext.tokenType,
          expires_in: tokens.accessTokenExpireIn,
          refresh_token: tokens.refreshToken,
        } as IToken);
      } catch (error) {
        /**
         * Invalid signature
         */
        return OauthHelper.throwError(req, res, {
          error: "invalid_grant",
          error_description: error.message,
        });
      }
    } catch (error) {
      console.log(error)
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      });
    }
  }
}

export default TokenGrantRefreshTokenHelper;
