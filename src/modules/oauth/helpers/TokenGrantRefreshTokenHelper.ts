import ITokenRequest from "../interfaces/ITokenRequest";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { IOauthClient } from "../models/OauthClient";
import { IOauthDefaults } from "../OauthDefaults";
import HttpStatus from "../../../common/HttpStatus";
import ITokenError from "../interfaces/ITokenError";
import { isQueryParamFilled } from "../../../common/Utils";
import OauthRefreshToken, {
  IOauthRefreshToken,
} from "../models/OauthRefreshToken";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import moment from "moment";
import IToken from "../interfaces/IToken";
import IAccessTokenPayload from "../interfaces/IAccessTokenPayload";

class TokenGrantRefreshTokenHelper {
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
       * REFRESH TOKEN VERIFICATION
       * *******************************
       */

      // Check if refresh token is within the request
      if (!isQueryParamFilled(data.refresh_token)) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description: `refresh_token is required.`,
          } as ITokenError,
        };
      }

      // load refresh token
      const oauthRefreshToken = await OauthRefreshToken.findOne({
        token: data.refresh_token,
      });

      // refresh token doesn't exist
      if (!oauthRefreshToken) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_grant",
            error_description: `Unknown refresh token.`,
          } as ITokenError,
        };
      }

      // refresh token expired
      if (oauthRefreshToken.expiresAt || oauthRefreshToken.revokedAt) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_grant",
            error_description: `The refresh token is expired or revoked.`,
          } as ITokenError,
        };
      }

      /**
       * Get refresh token data
       * *******************************
       */
      const refreshTokenData = jwt.verify(
        oauthRefreshToken.token,
        oauthParams.OAUTH_SECRET_KEY,
        {
          algorithms: [oauthParams.OAUTH_JWT_ALGORITHM],
        }
      ) as IOauthAccessToken;

      /**
       * Verify client_id
       * *******************************
       */
      if (data.client_id !== refreshTokenData.client.clientId) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_grant",
            error_description: `Invalid refresh token. client_id does not match.`,
          } as ITokenError,
        };
      }

      /**
       * Verify scope
       * *******************************
       */

      // new access token scope, identical with the previous by default
      let newAccessTokenScope = refreshTokenData.scope;

      if (data.scope && refreshTokenData.scope) {
        const currentScopes = refreshTokenData.scope.split(" ");
        const newScopes = data.scope.split(" ");
        for (const scope of newScopes) {
          if (currentScopes.includes(scope)) {
            throw {
              status: HttpStatus.BadRequest,
              data: {
                error: "invalid_scope",
                error_description: `${scope} is already in the previous access token scope.`,
              } as ITokenError,
            };
          } else {
            currentScopes.push(scope);
          }
        }
        // update new access token scope
        newAccessTokenScope = currentScopes.join(" ");
      }

      /**
       * Revoke the refresh token
       * *******************************
       */
      oauthRefreshToken.set({ revokedAt: new Date() });
      oauthRefreshToken.save();

      /**
       * GENERATE NEW ACCESS TOKEN AND REFRESH_TOKEN
       * *******************************************
       */

      // access token expires at
      const accessTokenExpiresAt = moment()
        .add(oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN, "seconds")
        .toDate();

      // refresh token expires at
      const refreshTokenExpiresAt = moment()
        .add(oauthParams.OAUTH_REFRESH_TOKEN_EXPIRE_IN, "seconds")
        .toDate();

      /**
       * Create and save oauth access token data
       */
      const oauthAccessToken = new OauthAccessToken({
        userId: refreshTokenData.userId,
        client: client._id,
        name: client.name,
        scope: newAccessTokenScope,
        expiresAt: accessTokenExpiresAt,
      } as Partial<IOauthAccessToken>);

      await oauthAccessToken.save();

      // refresh token
      const refreshToken = jwt.sign(
        oauthAccessToken.toJSON(),
        oauthParams.OAUTH_SECRET_KEY,
        {
          algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
          expiresIn: oauthParams.OAUTH_REFRESH_TOKEN_EXPIRE_IN,
          issuer: oauthParams.OAUTH_ISSUER, // must be provided
        }
      );

      /**
       * Save refresh token data
       */
      const newOauthRefreshToken = new OauthRefreshToken({
        token: refreshToken,
        expiresAt: refreshTokenExpiresAt,
      } as Partial<IOauthRefreshToken>);

      // save refresh token
      await newOauthRefreshToken.save();

      // revoke previous access token
      await OauthAccessToken.updateMany(
        {
          _id: { $ne: oauthAccessToken._id },
          userId: client.clientId,
        },
        {
          revokedAt: new Date(),
        }
      );

      /**
       * Create JWT token
       * ******************************
       */
      const token = jwt.sign(
        {
          tokenId: oauthAccessToken._id.toString(),
          userId: refreshTokenData.userId,
          client: client._id.toString(),
          scope: newAccessTokenScope,
        } as IAccessTokenPayload,
        oauthParams.OAUTH_SECRET_KEY,
        {
          algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
          expiresIn: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
          issuer: oauthParams.OAUTH_ISSUER, // must be provided
        }
      );

      return res.status(HttpStatus.Ok).json({
        access_token: token,
        token_type: oauthParams.OAUTH_TOKEN_TYPE,
        expires_in: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
        refresh_token: refreshToken,
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

export default TokenGrantRefreshTokenHelper;
