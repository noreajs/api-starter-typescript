import { Request, Response } from "express";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import { IOauthClient } from "../models/OauthClient";
import HttpStatus from "../../../common/HttpStatus";
import UrlHelper from "../helpers/UrlHelper";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import moment from "moment";
import { v4 as uuidV4 } from "uuid";
import { suid } from "rand-token";
import IToken from "../interfaces/IToken";
import IAuthorizationResponse from "../interfaces/IAuthorizationResponse";
import UtilsHelper from "../helpers/UtilsHelper";
import path from "path";
import OauthHelper from "../helpers/OauthHelper";
import OauthController from "./oauth.controller";

class AuthorizationController extends OauthController {
  OAUTH_DIALOG_PATH = "oauth/v2/dialog";
  OAUTH_AUTHORIZE_PATH = "oauth/v2/authorize";

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
    // const payload = JSON.parse(
    //   Buffer.from(req.query.p, "base64").toString("ascii")
    // ) as {
    //   oauthAuthCodeId: string;
    //   order?: "cancel";
    //   inputs?: {
    //     [key: string]: string;
    //   };
    //   error?: {
    //     message: string;
    //     errors: {
    //       [key: string]: string;
    //     };
    //   };
    // };

    if (req.session) {
      const payload = {
        oauthAuthCodeId: req.session.oauthAuthCodeId,
        error: req.session.error,
        inputs: req.session.inputs,
        order: req.query.order,
      } as {
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
          return OauthHelper.throwError(
            req,
            res,
            {
              error: "access_denied",
              error_description: "The resource owner denied the request.",
              state: oauthCode.state,
            },
            oauthCode.redirectUri
          );
        } else {
          return res.render(authLoginPath, {
            providerName: this.oauthContext.providerName,
            currentYear: new Date().getFullYear(),
            oauthAuthCodeId: oauthCode._id,
            formAction: `${UrlHelper.getFullUrl(req)}/${
              this.OAUTH_AUTHORIZE_PATH
            }`,
            cancelUrl: `${UrlHelper.getFullUrl(req)}/${
              this.OAUTH_DIALOG_PATH
            }?p=${Buffer.from(
              JSON.stringify({
                oauthAuthCodeId: oauthCode._id,
                order: "cancel",
              })
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
        return OauthHelper.throwError(req, res, {
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        });
      }
    } else {
      // no session
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
      });
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
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "unsupported_response_type",
            error_description:
              "Expected value for response_type are 'token' and 'code'",
            state: data.state,
          },
          data.redirect_uri
        );
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
          .add(this.oauthContext.authorizationCodeLifeTime, "seconds")
          .toDate(),
      } as Partial<IOauthAuthCode>);

      // save codes
      await oauthCode.save();

      // set session
      if (req.session) {
        req.session.oauthAuthCodeId = oauthCode._id;
      } else {
        throw Error("No session defined. Express session required.");
      }

      return res.redirect(
        HttpStatus.TemporaryRedirect,
        `${UrlHelper.getFullUrl(req)}/${this.OAUTH_DIALOG_PATH}`
      );
    } catch (e) {
      console.log(e);
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        state: data.state,
      });
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

    /**
     * load auth code
     * *****************************************
     */
    const oauthCode = await OauthAuthCode.findById(formData.oauthAuthCodeId);

    if (oauthCode) {
      try {
        // checking required field
        const requiredFields = UtilsHelper.checkAttributes<any>(
          ["username", "password"],
          formData
        );
        
        if (requiredFields.length !== 0) {
          // set session
          if (req.session) {
            req.session.error = {
              message: `${requiredFields.join(", ")} ${
                requiredFields.length > 1 ? "are" : "is"
              } required.`,
            };
            req.session.inputs = formData;
          } else {
            throw Error("No session defined. Express session required.");
          }

          return res.redirect(
            HttpStatus.MovedPermanently,
            `${UrlHelper.getFullUrl(req)}/${this.OAUTH_DIALOG_PATH}`
          );
        }

        const endUserData = await this.oauthContext.authenticationLogic(
          formData.username,
          formData.password
        );

        if (!endUserData) {
          // set session
          if (req.session) {
            req.session.error = {
              message: `Given credentials are not valid or do not match any record.`,
            };
            req.session.inputs = formData;
          } else {
            throw Error("No session defined. Express session required.");
          }

          return res.redirect(
            HttpStatus.MovedPermanently,
            `${UrlHelper.getFullUrl(req)}/${this.OAUTH_DIALOG_PATH}`
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
          return OauthHelper.throwError(
            req,
            res,
            {
              error: "invalid_scope",
              error_description: "The request scope must be in client scope.",
            },
            oauthCode.redirectUri
          );
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

        /**
         * Authorization code
         */
        if (oauthCode.responseType === "code") {
          const authResponse = {
            code: authorizationCode,
            state: oauthCode.state,
          } as IAuthorizationResponse;
          return res.redirect(
            UrlHelper.injectQueryParams(oauthCode.redirectUri, authResponse)
          );
        } else if (oauthCode.responseType === "token") {
          /**
           * Implicit Grant
           */
          // user id
          const userId = uuidV4();

          const tokens = await oauthCode.client.newAccessToken({
            grant: "implicit",
            oauthContext: this.oauthContext,
            req: req,
            scope: mergedScope,
            subject: userId,
          });

          const authResponse = {
            access_token: tokens.token,
            token_type: this.oauthContext.tokenType,
            expires_in: tokens.accessTokenExpireIn,
            state: oauthCode.state,
          } as IToken;

          return res.redirect(
            UrlHelper.injectQueryParams(oauthCode.redirectUri, authResponse)
          );
        } else {
          /**
           * Unsupported response type
           */
          return OauthHelper.throwError(
            req,
            res,
            {
              error: "unsupported_response_type",
            },
            oauthCode.redirectUri
          );
        }
      } catch (e) {
        console.log("e");
        return OauthHelper.throwError(req, res, {
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
          state: oauthCode.state,
        });
      }
    } else {
      return OauthHelper.throwError(req, res, {
        error: "access_denied",
        error_description: "Request denied. Data is corrupt.",
      });
    }
  };
}

export default AuthorizationController;
