import ITokenRequest from "../interfaces/ITokenRequest";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { IOauthClient } from "../models/OauthClient";
import HttpStatus from "../../../common/HttpStatus";
import OauthRefreshToken from "../models/OauthRefreshToken";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import moment from "moment";
import IToken from "../interfaces/IToken";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import OauthHelper from "./OauthHelper";
import UtilsHelper from "./UtilsHelper";
import { IRequiredOauthContext } from "../OauthContext";

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
    oauthContext: IRequiredOauthContext
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
         * ACCESS TOKEN AND REFRESH_TOKEN
         * *******************************************
         */

        // access token expires at
        const accessTokenExpiresAt = moment()
          .add(oauthContext.accessTokenExpiresIn.public.external, "seconds")
          .toDate();

        /**
         * Update and save oauth access token data
         */
        await OauthAccessToken.updateOne(
          {
            _id: oauthRefreshToken.accessToken._id,
          },
          {
            scope: newAccessTokenScope,
            expiresAt: accessTokenExpiresAt,
          } as Partial<IOauthAccessToken>
        );

        /**
         * Save refresh attempts
         * *********************************************
         */
        const attemps = oauthRefreshToken.attemps ?? [];
        attemps.push({
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          attemptedAt: new Date(),
        });

        await OauthRefreshToken.updateOne(
          {
            _id: oauthRefreshToken._id,
          },
          {
            attemps: attemps,
          } as Partial<IOauthAccessToken>
        );

        /**
         * Create JWT token
         * ******************************
         */
        const token = OauthHelper.jwtSign(req, oauthContext, {
          client_id: client.clientId,
          scope: newAccessTokenScope,
          azp: client.clientId,
          aud: client.clientId,
          sub: oauthRefreshToken.accessToken.userId,
          jti: oauthRefreshToken.accessToken._id.toString(),
          exp: accessTokenExpiresAt.getTime(),
        });

        return res.status(HttpStatus.Ok).json({
          access_token: token,
          token_type: oauthContext.tokenType,
          expires_in: oauthContext.refreshTokenExpiresIn.public.external,
          refresh_token: data.refresh_token,
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
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      });
    }
  }
}

export default TokenGrantRefreshTokenHelper;
