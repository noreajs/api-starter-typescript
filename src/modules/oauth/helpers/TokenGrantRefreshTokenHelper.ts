import ITokenRequest from "../interfaces/ITokenRequest";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { ObjectId } from "bson";
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
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import OauthHelper from "./OauthHelper";

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

      /**
       * Get refresh token data
       * *******************************
       */
      await jwt.verify(
        data.refresh_token,
        oauthParams.OAUTH_SECRET_KEY,
        {
          algorithms: [oauthParams.OAUTH_JWT_ALGORITHM],
        },
        async (error, refreshTokenData: IJwtTokenPayload) => {
          try {
            if (error) {
              /**
               * Invalid signature
               */
              throw {
                status: HttpStatus.BadRequest,
                data: {
                  error: "invalid_grant",
                  error_description: error.message,
                } as ITokenError,
              };
            } else {
              // load refresh token
              const oauthRefreshToken = await OauthRefreshToken.findOne({
                _id: refreshTokenData.jti,
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
              if (moment().isAfter(oauthRefreshToken.expiresAt)) {
                throw {
                  status: HttpStatus.BadRequest,
                  data: {
                    error: "invalid_grant",
                    error_description: `The refresh token is expired.`,
                  } as ITokenError,
                };
              }

              // refresh token revoked
              if (oauthRefreshToken.revokedAt) {
                throw {
                  status: HttpStatus.BadRequest,
                  data: {
                    error: "invalid_grant",
                    error_description: `The refresh token is revoked.`,
                  } as ITokenError,
                };
              }

              /**
               * Verify client_id
               * *******************************
               */
              if (data.client_id !== refreshTokenData.client_id) {
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
              let newAccessTokenScope = oauthRefreshToken.accessToken.scope;

              if (data.scope && newAccessTokenScope) {
                const currentScopes = newAccessTokenScope.split(" ");
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
               * ACCESS TOKEN AND REFRESH_TOKEN
               * *******************************************
               */

              // access token expires at
              const accessTokenExpiresAt = moment()
                .add(oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN, "seconds")
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
              const token = OauthHelper.jwtSign(req, oauthParams, {
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
                token_type: oauthParams.OAUTH_TOKEN_TYPE,
                expires_in: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
                refresh_token: data.refresh_token,
              } as IToken);
            }
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
      );
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
