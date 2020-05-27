import { Request, Response } from "express";
import crypto from "crypto";
import { IOauthDefaults } from "../OauthDefaults";
import HttpStatus from "../../../common/HttpStatus";
import IToken from "../interfaces/IToken";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import OauthAuthCode from "../models/OauthAuthCode";
import OauthRefreshToken, {
  IOauthRefreshToken,
} from "../models/OauthRefreshToken";
import moment from "moment";
import jwt from "jsonwebtoken";
import { IOauthClient } from "../models/OauthClient";
import ITokenRequest from "../interfaces/ITokenRequest";
import ICodeChallengeMethodType from "../interfaces/ICodeChallengeMethodType";
import { toASCII } from "punycode";
import ITokenError from "../interfaces/ITokenError";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import OauthHelper from "./OauthHelper";

class TokenGrantAuthorizationCodeHelper {
  /**
   * Get Authorization Code Grant
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
       * AUTHORIZATION CODE VALIDATION
       * *********************************
       */

      // load authoriation token
      const oauthCode = await OauthAuthCode.findOne({
        client: client._id,
        authorizationCode: data.code,
      });

      if (oauthCode) {
        if (moment().isAfter(oauthCode.expiresAt)) {
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "invalid_grant",
              error_description:
                "The authorization code has been expired. Try to get another one.",
            } as ITokenError,
          };
        } else if (oauthCode.revokedAt) {
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "invalid_grant",
              error_description:
                "The authorization code has been revoked. Try to get another one.",
            } as ITokenError,
          };
        } else {
          /**
           * Verify authorization code
           * *****************************
           */
          const hashedCode = crypto
            .createHmac(
              oauthParams.OAUTH_HMAC_ALGORITHM,
              oauthParams.OAUTH_SECRET_KEY
            )
            .update(oauthCode.userId)
            .digest("hex");

          /**
           * Wrong token.. Wizard on board
           */
          if (hashedCode !== data.code) {
            throw {
              status: HttpStatus.BadRequest,
              data: {
                error: "invalid_grant",
                error_description:
                  "The authorization code in not valid or corrupted.",
              } as ITokenError,
            };
          }

          /**
           * Redirect URI must match
           */
          if (oauthCode.redirectUri !== data.redirect_uri) {
            throw {
              status: HttpStatus.BadRequest,
              data: {
                error: "invalid_grant",
                error_description: `The redirect_uri parameter must be identical to the one included in the authorization request.`,
              } as ITokenError,
            };
          }

          /**
           * Code verifier check
           */
          if (oauthCode.codeChallenge) {
            if (!data.code_verifier) {
              throw {
                status: HttpStatus.BadRequest,
                data: {
                  error: "invalid_request",
                  error_description: `The "code_verifier" is required.`,
                } as ITokenError,
              };
            } else {
              switch (oauthCode.codeChallengeMethod) {
                case "plain":
                  if (data.code_verifier !== oauthCode.codeChallenge) {
                    throw {
                      status: HttpStatus.BadRequest,
                      data: {
                        error: "invalid_grant",
                        error_description: `Code verifier and code challenge are not identical.`,
                      } as ITokenError,
                    };
                  }
                  break;
                case "S256":
                  // code here
                  const hashed = crypto
                    .createHash("sha256")
                    .update(toASCII(data.code_verifier))
                    .digest("base64")
                    .replace(/=/g, "")
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_");

                  if (hashed !== oauthCode.codeChallenge) {
                    throw {
                      status: HttpStatus.BadRequest,
                      data: {
                        error: "invalid_grant",
                        error_description: `Hashed code verifier and code challenge are not identical.`,
                      } as ITokenError,
                    };
                  }

                  break;
              }
            }
          }

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
           * ******************************************
           */
          const oauthAccessToken = new OauthAccessToken({
            userId: oauthCode.userId,
            client: client._id,
            name: client.name,
            scope: oauthCode.scope,
            expiresAt: accessTokenExpiresAt,
          } as Partial<IOauthAccessToken>);

          // save access token
          await oauthAccessToken.save();

          // refresh token
          const refreshToken = jwt.sign(
            { client_id: client.clientId } as IJwtTokenPayload,
            oauthParams.OAUTH_SECRET_KEY,
            {
              algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
              expiresIn: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
              issuer: OauthHelper.getFullUrl(req),
              audience: client.clientId,
              subject: oauthCode.userId,
              jwtid: oauthAccessToken._id.toString(),
            }
          );

          /**
           * Save refresh token data
           */
          const oauthRefreshToken = new OauthRefreshToken({
            token: refreshToken,
            expiresAt: refreshTokenExpiresAt,
          } as Partial<IOauthRefreshToken>);

          // save refresh token
          await oauthRefreshToken.save();

          // revoke previous authorization code
          await OauthAuthCode.updateMany(
            {
              userId: oauthCode.userId,
            },
            {
              revokedAt: new Date(),
            }
          );

          // revoke previous access token
          await OauthAccessToken.updateMany(
            {
              _id: { $ne: oauthAccessToken._id },
              userId: oauthCode.userId,
            },
            {
              revokedAt: new Date(),
            }
          );

          /**
           * Create JWT token
           * ************************************
           */
          const token = jwt.sign(
            {
              client_id: client.clientId,
              scope: oauthCode.scope,
            } as IJwtTokenPayload,
            oauthParams.OAUTH_SECRET_KEY,
            {
              algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
              expiresIn: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
              issuer: OauthHelper.getFullUrl(req),
              audience: client.clientId,
              subject: oauthCode.userId,
              jwtid: oauthAccessToken._id.toString(),
            }
          );

          return res.status(HttpStatus.Ok).json({
            access_token: token,
            token_type: oauthParams.OAUTH_TOKEN_TYPE,
            expires_in: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
            refresh_token: refreshToken,
          } as IToken);
        }
      } else {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_grant",
            error_description: `The authorization code is not valid.`,
          } as ITokenError,
        };
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
}

export default TokenGrantAuthorizationCodeHelper;
