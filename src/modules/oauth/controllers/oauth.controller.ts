import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { v4 as uuidV4 } from "uuid";
import crypto from "crypto";
import HttpStatus from "../../../common/HttpStatus";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import OauthClient from "../models/OauthClient";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import ITokenRequest from "../interfaces/ITokenRequest";
import moment from "moment";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import IToken from "../interfaces/IToken";
import OauthDefaults, { IOauthDefaults } from "../OauthDefaults";
import { isQueryParamFilled } from "../../../common/Utils";
import OauthHelper from "../helpers/OauthHelper";
import IAuthorizationErrorResponse from "../interfaces/IAuthorizationErrorResponse";
import IAuthorizationResponse from "../interfaces/IAuthorizationResponse";
import UrlHelper from "../helpers/UrlHelper";
import ITokenError from "../interfaces/ITokenError";
import TokenGrantAuthorizationCodeHelper from "../helpers/TokenGrantAuthorizationCodeHelper";
import TokenGrantClientCredentialsHelper from "../helpers/TokenGrantClientCredentialsHelper";
import TokenGrantPasswordCredentialsHelper from "../helpers/TokenGrantPasswordCredentialsHelper";
import TokenGrantRefreshTokenHelper from "../helpers/TokenGrantRefreshTokenHelper";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import UtilsHelper from "../helpers/UtilsHelper";

class OauthController {
  oauthParams: IOauthDefaults;

  constructor() {
    this.oauthParams = OauthDefaults;
  }

  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  authorize = async (req: Request, res: Response) => {
    // get request query data
    let data: IAuthCodeRequest = req.query as IAuthCodeRequest;

    try {
      /**
       * Required parameters
       */
      const requiredParameters = UtilsHelper.checkAttributes<IAuthCodeRequest>(
        ["response_type", "redirect_uri", "client_id"],
        data
      );

      if (requiredParameters.length != 0) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description: `${requiredParameters.join(", ")} ${
              requiredParameters.length > 1 ? "are required" : "is required"
            }`,
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Code challenge method validation
       */
      if (
        data.code_challenge_method &&
        !["plain", "S256"].includes(data.code_challenge_method)
      ) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_request",
            error_description: `The code challenge method must be "plain" or "S256"`,
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      // load client
      const client = await OauthClient.findOne({ clientId: data.client_id });

      /**
       * Client has to exist
       */
      if (!client) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description: "Unknown client",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      if (!client.redirectURIs.includes(data.redirect_uri)) {
        throw {
          status: HttpStatus.BadRequest,
          redirect: false,
          data: {
            error: "invalid_request",
            error_description:
              "Given redirect uri is not in the client redirect URIs",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Authentificate client
       * ***************************************
       */

      // Client revoked
      if (client.revokedAt) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "access_denied",
            error_description:
              "The client related to this request has been revoked.",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      /**
       * Check scopes
       * ****************
       */
      if (data.scope && !client.validateScope(data.scope)) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_scope",
            error_description: "The request scope must be in client scopes.",
          } as ITokenError,
        };
      }

      /**
       *
       *
       * Response type
       *
       */
      if (!["code", "token"].includes(data.response_type)) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "unsupported_response_type",
            error_description:
              "Expected value for response_type are 'token' and 'code'",
            state: data.state,
          } as IAuthorizationErrorResponse,
        };
      }

      // check response type
      if (data.response_type === "code") {
        /**
         * AUTHORIZATION CODE GENERATION
         * ***********************************
         */

        const userId = uuidV4(); // if authorization has been skipped

        // Authorization code
        const authorizationCode = crypto
          .createHmac(
            this.oauthParams.OAUTH_HMAC_ALGORITHM,
            this.oauthParams.OAUTH_SECRET_KEY
          )
          .update(userId)
          .digest("hex");

        /**
         * Revoke other authorization code
         */
        await OauthAuthCode.updateMany(
          {
            userId: userId,
          },
          {
            revokedAt: new Date(),
          }
        );

        // create oauth code
        const oauthCode = new OauthAuthCode({
          userId: userId,
          authorizationCode: authorizationCode,
          client: client._id,
          scope: data.scope,
          codeChallenge: data.code_challenge,
          codeChallengeMethod: data.code_challenge_method,
          redirectUri: data.redirect_uri,
          expiresAt: moment()
            .add(this.oauthParams.OAUTH_AUTHORIZATION_CODE_LIFE_TIME, "seconds")
            .toDate(),
        } as Partial<IOauthAuthCode>);

        // save codes
        await oauthCode.save();

        const authResponse = {
          code: authorizationCode,
          state: data.state,
        } as IAuthorizationResponse;

        return res.redirect(
          UrlHelper.injectQueryParams(data.redirect_uri, authResponse)
        );
      } else if (data.response_type === "token") {
        // user id
        const userId = uuidV4();

        const tokens = await client.newAccessToken({
          grant: "implicit",
          oauthParams: this.oauthParams,
          req: req,
          scope: data.scope ?? "",
          subject: userId,
        });

        const authResponse = {
          access_token: tokens.token,
          token_type: this.oauthParams.OAUTH_TOKEN_TYPE,
          expires_in: tokens.accessTokenExpireIn,
          state: data.state,
        } as IToken;

        return res.redirect(
          UrlHelper.injectQueryParams(data.redirect_uri, authResponse)
        );
      } else {
        throw {
          message: "Wizard! please how do you get here?",
        };
      }
    } catch (e) {
      if (e.status) {
        if (e.redirect !== false) {
          return res.redirect(
            UrlHelper.injectQueryParams(data.redirect_uri, e.data)
          );
        } else {
          return res.status(e.status).json(e.data);
        }
      } else {
        console.log(e);
        return res.status(HttpStatus.BadRequest).json({
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
          state: data.state,
        } as IAuthorizationErrorResponse);
      }
    }
  };

  /**
   * Generate token
   * @param req request
   * @param res response
   */
  async callback(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      query: req.query,
      body: req.body,
    });
  }

  /**
   * Generate token
   * @param req request
   * @param res response
   */
  token = async (req: Request, res: Response) => {
    // request data
    let data: ITokenRequest = req.body as ITokenRequest;

    // get basic auth header credentials
    let basicAuthCredentials = OauthHelper.getBasicAuthHeaderCredentials(req);

    // update credential if exist
    if (basicAuthCredentials) {
      data.client_id = basicAuthCredentials.client_id;
      data.client_secret = basicAuthCredentials.client_secret;
    }

    try {
      if (!data.client_id) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_request",
            error_description:
              "The client_id is required. You can send it with client_secret in body or via Basic Auth header.",
          } as ITokenError,
        };
      }

      // load client
      const client = await OauthClient.findOne({ clientId: data.client_id });

      /**
       * Client has to exist
       */
      if (!client) {
        throw {
          status: HttpStatus.Unauthorized,
          data: {
            error: "invalid_client",
            error_description: "Unknown client",
          } as ITokenError,
        };
      }

      // Client revoked
      if (client.revokedAt) {
        throw {
          status: HttpStatus.Unauthorized,
          data: {
            error: "invalid_client",
            error_description:
              "The client related to this request has been revoked.",
          } as ITokenError,
        };
      }

      /**
       * Check scopes
       * ****************
       */
      if (data.scope && !client.validateScope(data.scope)) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_scope",
            error_description:
              "The requested scope is invalid, unknown, malformed, or exceeds the scope granted.",
          } as ITokenError,
        };
      }

      if (client.clientType === "confidential" && !data.client_secret) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_request",
            error_description:
              "The secret_secret is required for confidential client. You can send it with client_id in body or via Basic Auth header.",
          } as ITokenError,
        };
      }

      /**
       * Verify secret code if it exist
       */
      if (
        data.client_secret &&
        data.client_secret.length !== 0 &&
        !OauthHelper.verifyClientSecret({
          clientId: client.clientId,
          hash: data.client_secret,
          oauthHmacAlgorithm: this.oauthParams.OAUTH_HMAC_ALGORITHM,
          oauthSecretKey: this.oauthParams.OAUTH_SECRET_KEY,
        })
      ) {
        throw {
          status: HttpStatus.Unauthorized,
          data: {
            error: "invalid_client",
            error_description: "Invalid client secret.",
          } as ITokenError,
        };
      }

      switch (data.grant_type) {
        case "authorization_code":
          // Authorization Code Grant
          return TokenGrantAuthorizationCodeHelper.run(
            req,
            res,
            data,
            client,
            this.oauthParams
          );
        case "client_credentials":
          // Client Credentials Grant
          return TokenGrantClientCredentialsHelper.run(
            req,
            res,
            data,
            client,
            this.oauthParams
          );
        case "password":
          // Resource Owner Password Credentials
          return TokenGrantPasswordCredentialsHelper.run(
            req,
            res,
            data,
            client,
            this.oauthParams
          );
        case "refresh_token":
          // Refreshing an Access Token
          return TokenGrantRefreshTokenHelper.run(
            req,
            res,
            data,
            client,
            this.oauthParams
          );
        default:
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "unsupported_grant_type",
              error_description:
                "The authorization grant type is not supported by the authorization server.",
            } as ITokenError,
          };
      }
    } catch (e) {
      if (e.status) {
        return res.status(e.status).json(e.data);
      } else {
        console.log(e);
        return res.status(HttpStatus.BadRequest).json({
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        } as ITokenError);
      }
    }
  };

  /**
   * Purge expired and revoked token
   * @param req request
   * @param res response
   */
  async purge(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      message: "Purge",
    });
  }

  /**
   * Get authorization dialog
   * @param req request
   * @param res response
   */
  async dialog(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      message: "Dialog",
    });
  }

  /**
   * Get information about a token
   * @param req request
   * @param res response
   */
  async inspect(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      message: "Inspect token",
    });
  }
}

export default new OauthController();
