import { Request, Response } from "express";
import jwt from "jsonwebtoken";
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
import SecretHelper from "../helpers/SecretHelper";
import IAuthorizationErrorResponse from "../interfaces/IAuthorizationErrorResponse";
import IAuthorizationResponse from "../interfaces/IAuthorizationResponse";
import UrlHelper from "../helpers/UrlHelper";
import ITokenError from "../interfaces/ITokenError";
import TokenGrantAuthorizationCodeHelper from "../helpers/TokenGrantAuthorizationCodeHelper";
import TokenGrantClientCredentialsHelper from "../helpers/TokenGrantClientCredentialsHelper";
import TokenGrantPasswordCredentialsHelper from "../helpers/TokenGrantPasswordCredentialsHelper";

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

    // Required parameters
    const requiredParameters = [];

    try {
      /**
       * Required parameters
       */
      if (!isQueryParamFilled(data.response_type)) {
        requiredParameters.push("response_type");
      }

      if (!isQueryParamFilled(data.redirect_uri)) {
        requiredParameters.push("redirect_uri");
      }

      if (!isQueryParamFilled(data.client_id)) {
        requiredParameters.push("client_id");
      }

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
       *
       * Authentificate client
       *
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
       *
       *
       * Checking Scope validity
       *
       *
       */
      if (data.scope && client.scope) {
        const requestScopes = data.scope.split(" ");
        const clientScopes = client.scope.split(" ");

        let missingScopeFound = false;

        for (const scope of requestScopes) {
          if (!clientScopes.includes(scope)) {
            missingScopeFound = true;
            break;
          }
        }

        if (missingScopeFound) {
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "invalid_scope",
              error_description:
                "The requested scope is invalid, unknown, or malformed.",
              state: data.state,
            } as IAuthorizationErrorResponse,
          };
        }
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
        // Authorization code
        const authorizationCode = jwt.sign(
          {
            redirect_uri: data.redirect_uri,
            client_id: client.clientId,
            code_challenge: data.code_challenge,
            code_challenge_method: data.code_challenge_method,
          },
          this.oauthParams.OAUTH_SECRET_KEY,
          {
            algorithm: this.oauthParams.OAUTH_JWT_ALGORITHM,
            expiresIn: this.oauthParams.OAUTH_AUTHORIZATION_CODE_LIFE_TIME,
            issuer: this.oauthParams.OAUTH_ISSUER, // must be provided
          }
        );

        /**
         * Revoke other authorization code
         */
        await OauthAuthCode.updateMany(
          {
            client: client._id,
          },
          {
            revokedAt: new Date(),
          }
        );

        // create oauth code
        const oauthCode = new OauthAuthCode({
          authorizationCode: authorizationCode,
          client: client._id,
          scope: data.scope,
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
        // expires at
        const expiresAt = moment()
          .add(this.oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN, "seconds")
          .toDate();
        // Create token
        const token = jwt.sign(
          {
            userId: client.clientId,
            client: client._id.toString(),
            scope: data.scope,
          },
          this.oauthParams.OAUTH_SECRET_KEY,
          {
            algorithm: this.oauthParams.OAUTH_JWT_ALGORITHM,
            expiresIn: this.oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
            issuer: this.oauthParams.OAUTH_ISSUER,
            // must be provided
          }
        );

        /**
         * Save access token data
         */
        const oauthAccessToken = new OauthAccessToken({
          userId: client.clientId,
          client: client._id,
          name: client.name,
          scope: data.scope,
          expiresAt: expiresAt,
        } as Partial<IOauthAccessToken>);

        await oauthAccessToken.save();

        const authResponse = {
          access_token: token,
          token_type: "Bearer",
          expires_in: this.oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
          state: data.state,
        } as IToken;

        return res.redirect(
          UrlHelper.injectQueryParams(data.redirect_uri, authResponse)
        );
      } else {
        throw {
          message: "Wizard! please how do you get here",
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
    let basicAuthCredentials = SecretHelper.getBasicAuthHeaderCredentials(req);

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
       *
       * Checking Scope validity
       *
       */
      if (data.scope && client.scope) {
        const requestScopes = data.scope.split(" ");
        const clientScopes = client.scope.split(" ");

        let missingScopeFound = false;

        for (const scope of requestScopes) {
          if (!clientScopes.includes(scope)) {
            missingScopeFound = true;
            break;
          }
        }

        if (missingScopeFound) {
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "invalid_scope",
              error_description:
                "The requested scope is invalid, unknown, malformed, or exceeds the scope granted."
            } as ITokenError,
          };
        }
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
        !SecretHelper.verifyClientSecret({
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
}

export default new OauthController();
