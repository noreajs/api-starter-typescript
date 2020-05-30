import { Request, Response } from "express";
import { v4 as uuidV4 } from "uuid";
import crypto from "crypto";
import HttpStatus from "../../../common/HttpStatus";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import OauthClient, { IOauthClient } from "../models/OauthClient";
import OauthAuthCode from "../models/OauthAuthCode";
import ITokenRequest from "../interfaces/ITokenRequest";
import OauthDefaults, { IOauthDefaults } from "../OauthDefaults";
import OauthHelper from "../helpers/OauthHelper";
import UrlHelper from "../helpers/UrlHelper";
import ITokenError from "../interfaces/ITokenError";
import TokenGrantAuthorizationCodeHelper from "../helpers/TokenGrantAuthorizationCodeHelper";
import TokenGrantClientCredentialsHelper from "../helpers/TokenGrantClientCredentialsHelper";
import TokenGrantPasswordCredentialsHelper from "../helpers/TokenGrantPasswordCredentialsHelper";
import TokenGrantRefreshTokenHelper from "../helpers/TokenGrantRefreshTokenHelper";
import path from "path";
import IAuthorizationErrorResponse from "../interfaces/IAuthorizationErrorResponse";

class OauthController {
  oauthParams: IOauthDefaults;

  constructor() {
    this.oauthParams = OauthDefaults;
  }

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
}

export default new OauthController();
