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
import IEndUserAuthData from "../interfaces/IEndUserAuthData";
import ISessionCurrentData from "../interfaces/ISessionCurrentData";
import AuthorizationHelper from "../helpers/AuthorizationHelper";

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
      "login",
      "login.ejs"
    );

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
            formAction: `${UrlHelper.getFullUrl(req)}/${
              this.OAUTH_AUTHORIZE_PATH
            }`,
            cancelUrl: `${UrlHelper.getFullUrl(req)}/${
              this.OAUTH_DIALOG_PATH
            }?order=cancel`,
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
        // current user
        const currentData: ISessionCurrentData = req.session.currentData;

        if (currentData) {
          return await AuthorizationHelper.run(
            req,
            res,
            oauthCode,
            currentData
          );
        } else {
          req.session.oauthAuthCodeId = oauthCode._id;
        }
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
      username: string;
      password: string;
    };

    /**
     * load auth code
     * *****************************************
     */
    const oauthCode = await OauthAuthCode.findById(
      req.session?.oauthAuthCodeId
    );

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
         * Refresh session for next use, Save current user data
         * **********************************************
         */
        req.session?.regenerate(function (err) {
          if (err) {
            throw Error("Failed to regenerate session.");
          } else {
            const currentData: ISessionCurrentData = {
              responseType: oauthCode.responseType,
              authData: endUserData,
            };

            if (req.session) {
              req.session.currentData = currentData;
            } else {
              throw Error("Unable to access to session");
            }
          }
        });

        return await AuthorizationHelper.run(req, res, oauthCode, {
          responseType: oauthCode.responseType,
          authData: endUserData,
        });
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
