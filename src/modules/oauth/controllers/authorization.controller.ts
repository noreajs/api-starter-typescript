import OauthDefaults, { IOauthDefaults } from "../OauthDefaults";
import { Request, Response } from "express";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import { IOauthClient } from "../models/OauthClient";
import HttpStatus from "../../../common/HttpStatus";
import IAuthorizationErrorResponse from "../interfaces/IAuthorizationErrorResponse";
import UrlHelper from "../helpers/UrlHelper";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import moment from "moment";
import { v4 as uuidV4 } from "uuid";
import { suid } from "rand-token";
import IToken from "../interfaces/IToken";
import ITokenError from "../interfaces/ITokenError";
import IAuthorizationResponse from "../interfaces/IAuthorizationResponse";
import UtilsHelper from "../helpers/UtilsHelper";
import path from 'path';

class AuthorizationController {
  oauthParams: IOauthDefaults;

  constructor() {
    this.oauthParams = OauthDefaults;
  }

  /**
   * Get authorization dialog
   * @param req request
   * @param res response
   */
  dialog = async (req: Request, res: Response) => {
    // login path
    const authLoginPath = path.join(
      __dirname,
      "..",
      "views",
      "pages",
      "auth-login.ejs"
    );

    // request payload
    const payload = JSON.parse(
      Buffer.from(req.query.p, "base64").toString("ascii")
    ) as {
      oauthAuthCodeId: string;
      order?: "cancel";
      inputs?: {
        [key: string]: string;
      };
      error?: {
        message: string;
        errors: {
          [key: string]: string;
        };
      };
    };

    // load auth code
    const oauthCode = await OauthAuthCode.findById(payload.oauthAuthCodeId);

    // load scopes
    if (oauthCode) {
      /**
       * Authentification cancelled
       * ******************************
       */
      if (payload.order === "cancel") {
        return res.redirect(
          UrlHelper.injectQueryParams(oauthCode.redirectUri, {
            error: "access_denied",
            error_description: "The resource owner denied the request.",
            state: oauthCode.state,
          } as IAuthorizationErrorResponse)
        );
      } else {
        return res.render(authLoginPath, {
          providerName: this.oauthParams.providerName,
          currentYear: new Date().getFullYear(),
          oauthAuthCodeId: oauthCode._id,
          formAction: `${UrlHelper.getFullUrl(req)}/oauth/authorize`,
          cancelUrl: `${UrlHelper.getFullUrl(req)}/oauth/dialog?p=${Buffer.from(
            JSON.stringify({ oauthAuthCodeId: oauthCode._id, order: "cancel" })
          ).toString("base64")}`,
          error: payload.error,
          inputs: payload.inputs ?? {
            username: "",
            password: "",
          },
          client: {
            name: oauthCode.client.name,
            domaine: oauthCode.client.domaine,
            logo: oauthCode.client.logo,
            description: oauthCode.client.description,
            internal: oauthCode.client.internal,
            clientType: oauthCode.client.clientType,
            clientProfile: oauthCode.client.clientProfile,
            scope: oauthCode.client.scope,
          } as Partial<IOauthClient>,
        });
      }
    } else {
      return res.status(HttpStatus.BadRequest).json({
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      } as IAuthorizationErrorResponse);
    }
  };

  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  authorize = async (req: Request, res: Response) => {
    // get request query data
    const data = res.locals.data as IAuthCodeRequest;
    // get client
    const client = res.locals.client as IOauthClient;

    try {
      /**
       * Response type
       * *****************************
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

      /**
       * AUTHORIZATION CODE GENERATION
       * ***********************************
       */

      // create oauth code
      const oauthCode = new OauthAuthCode({
        client: client._id,
        state: data.state,
        scope: data.scope,
        responseType: data.response_type,
        codeChallenge: data.code_challenge,
        codeChallengeMethod: data.code_challenge_method,
        redirectUri: data.redirect_uri,
        expiresAt: moment()
          .add(this.oauthParams.OAUTH_AUTHORIZATION_CODE_LIFE_TIME, "seconds")
          .toDate(),
      } as Partial<IOauthAuthCode>);

      // save codes
      await oauthCode.save();

      return res.redirect(
        HttpStatus.TemporaryRedirect,
        `${UrlHelper.getFullUrl(req)}/oauth/dialog?p=${Buffer.from(
          JSON.stringify({ oauthAuthCodeId: oauthCode._id })
        ).toString("base64")}`
      );
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
   * Authentification of an end-user from dialog view
   */
  authenticate = async (req: Request, res: Response) => {
    // Form data
    const formData = req.body as {
      oauthAuthCodeId: string;
      username: string;
      password: string;
    };

    // checking required field
    const requiredFields = UtilsHelper.checkAttributes<any>(
      ["username", "password"],
      formData
    );
    if (requiredFields.length !== 0) {
      return res.redirect(
        HttpStatus.MovedPermanently,
        `${UrlHelper.getFullUrl(req)}/oauth/dialog?p=${Buffer.from(
          JSON.stringify({
            oauthAuthCodeId: formData.oauthAuthCodeId,
            error: {
              message: `${requiredFields.join(", ")} ${
                requiredFields.length > 1 ? "are" : "is"
              } required.`,
            },
            inputs: formData,
          })
        ).toString("base64")}`
      );
    }

    /**
     * load auth code
     * *****************************************
     */
    const oauthCode = await OauthAuthCode.findById(formData.oauthAuthCodeId);

    if (oauthCode) {
      try {
        const endUserData = await this.oauthParams.authenticationLogic(
          formData.username,
          formData.password,
          oauthCode.scope
        );

        if (!endUserData) {
          return res.redirect(
            HttpStatus.MovedPermanently,
            `${UrlHelper.getFullUrl(req)}/oauth/dialog?p=${Buffer.from(
              JSON.stringify({
                oauthAuthCodeId: formData.oauthAuthCodeId,
                error: {
                  message: `Given credentials are not valid or do not match any record.`,
                },
                inputs: formData,
              })
            ).toString("base64")}`
          );
        }

        /**
         * Check scopes
         * ****************
         */
        const mergedScope = oauthCode.client.mergedScope(
          endUserData.scope,
          oauthCode.scope
        );
        if (!mergedScope) {
          throw {
            status: HttpStatus.BadRequest,
            data: {
              error: "invalid_scope",
              error_description: "The request scope must be in client scope.",
            } as ITokenError,
          };
        }

        /**
         * Generate authorization code
         * ***********************************
         */
        const authorizationCode = suid(100);

        /**
         * Update oauth code
         */
        await OauthAuthCode.updateOne(
          {
            _id: oauthCode._id,
          },
          {
            userId: endUserData.userId,
            authorizationCode: authorizationCode,
          } as Partial<IOauthAuthCode>
        );

        // check response type
        if (oauthCode.responseType === "code") {
          const authResponse = {
            code: authorizationCode,
            state: oauthCode.state,
          } as IAuthorizationResponse;
          return res.redirect(
            UrlHelper.injectQueryParams(oauthCode.redirectUri, authResponse)
          );
        } else if (oauthCode.responseType === "token") {
          // user id
          const userId = uuidV4();

          const tokens = await oauthCode.client.newAccessToken({
            grant: "implicit",
            oauthParams: this.oauthParams,
            req: req,
            scope: mergedScope,
            subject: userId,
          });

          const authResponse = {
            access_token: tokens.token,
            token_type: this.oauthParams.OAUTH_TOKEN_TYPE,
            expires_in: tokens.accessTokenExpireIn,
            state: oauthCode.state,
          } as IToken;

          return res.redirect(
            UrlHelper.injectQueryParams(oauthCode.redirectUri, authResponse)
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
              UrlHelper.injectQueryParams(oauthCode.redirectUri, e.data)
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
            state: oauthCode.state,
          } as IAuthorizationErrorResponse);
        }
      }
    } else {
      return res.status(HttpStatus.BadRequest).json({
        error: "access_denied",
        error_description: "Request denied. Data is corrupt.",
      } as IAuthorizationErrorResponse);
    }
  };
}

export default new AuthorizationController();
