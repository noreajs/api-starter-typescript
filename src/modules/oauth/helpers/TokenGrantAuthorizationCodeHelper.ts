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
      // auth code
      const authorizationCode = await OauthAuthCode.findOne({
        client: client._id,
        authorizationCode: data.code,
      });

      if (authorizationCode) {
        if (moment().isAfter(authorizationCode.expiresAt)) {
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "invalid_grant",
              error_description:
                "The authorization code has been expired. Try to get another one.",
            } as ITokenError,
          };
        } else if (authorizationCode.revokedAt) {
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
           */
          const authorizationCodeData = jwt.verify(
            authorizationCode.authorizationCode,
            oauthParams.OAUTH_SECRET_KEY,
            {
              algorithms: [oauthParams.OAUTH_JWT_ALGORITHM],
            }
          ) as {
            client_id: string;
            redirect_uri: string;
            code_challenge?: string;
            code_challenge_method?: ICodeChallengeMethodType;
          };

          /**
           * Wrong token.. Wizard on board
           */
          if (authorizationCodeData.client_id !== client.clientId) {
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
          if (authorizationCodeData.redirect_uri !== data.redirect_uri) {
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
          if (authorizationCodeData.code_challenge) {
            if (!data.code_verifier) {
              throw {
                status: HttpStatus.BadRequest,
                data: {
                  error: "invalid_request",
                  error_description: `The "code_verifier" is required.`,
                } as ITokenError,
              };
            } else {
              switch (authorizationCodeData.code_challenge_method) {
                case "plain":
                  if (
                    data.code_verifier !== authorizationCodeData.code_challenge
                  ) {
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

                  if (hashed !== authorizationCodeData.code_challenge) {
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

          // expires at
          const expiresAt = moment()
            .add(oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN, "seconds")
            .toDate();
          // Create token
          const token = jwt.sign(
            {
              userId: client.clientId,
              client: client._id.toString(),
              scope: authorizationCode.scope,
            },
            oauthParams.OAUTH_SECRET_KEY,
            {
              algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
              expiresIn: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
              issuer: oauthParams.OAUTH_ISSUER, // must be provided
            }
          );

          /**
           * Save access token data
           */
          const oauthAccessToken = new OauthAccessToken({
            userId: client.clientId,
            client: client._id,
            name: client.name,
            scope: authorizationCode.scope,
            expiresAt: expiresAt,
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
          const oauthRefreshToken = new OauthRefreshToken({
            accessToken: refreshToken,
            expiresAt: expiresAt,
          } as Partial<IOauthRefreshToken>);

          // save refresh token
          await oauthRefreshToken.save();

          // revoke previous authorization code
          await OauthAuthCode.updateMany(
            {
              client: client._id,
            },
            {
              revokedAt: new Date(),
            }
          );

          // revoke previous access token
          await OauthAccessToken.updateMany(
            {
              userId: client.clientId,
            },
            {
              revokedAt: new Date(),
            }
          );

          return res.status(HttpStatus.Ok).json({
            access_token: token,
            token_type: "Bearer",
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
