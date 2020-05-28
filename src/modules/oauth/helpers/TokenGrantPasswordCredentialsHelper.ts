import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import { IOauthDefaults } from "../OauthDefaults";
import moment from "moment";
import jwt from "jsonwebtoken";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import OauthRefreshToken, {
  IOauthRefreshToken,
} from "../models/OauthRefreshToken";
import IToken from "../interfaces/IToken";
import HttpStatus from "../../../common/HttpStatus";
import { Request, Response } from "express";
import ITokenError from "../interfaces/ITokenError";
import { isQueryParamFilled } from "../../../common/Utils";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import OauthHelper from "./OauthHelper";

class TokenGrantPasswordCredentialsHelper {
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
      // Required parameters
      const requiredParameters = [];

      /**
       * Required parameters
       */
      if (!isQueryParamFilled(data.username)) {
        requiredParameters.push("username");
      }

      if (!isQueryParamFilled(data.password)) {
        requiredParameters.push("password");
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
          } as ITokenError,
        };
      }

      /**
       * Password Grant authentification data
       */
      const passwordGrantData = await oauthParams.passwordCredentialsGrantAuthLogic(
        data.username,
        data.password,
        data.scope
      );

      if (!passwordGrantData) {
        throw {
          status: HttpStatus.BadRequest,
          data: {
            error: "invalid_grant",
            error_description: `Given credentials are not valid or do not match any record.`,
          } as ITokenError,
        };
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
       * Save access token data
       */
      const oauthAccessToken = new OauthAccessToken({
        userId: passwordGrantData.userId,
        client: client._id,
        name: client.name,
        scope: passwordGrantData.scope,
        expiresAt: accessTokenExpiresAt,
        userAgent: req.headers["user-agent"],
      } as Partial<IOauthAccessToken>);

      await oauthAccessToken.save();

      // refresh token
      const refreshToken = jwt.sign(
        {
          client_id: client.clientId,
        } as IJwtTokenPayload,
        oauthParams.OAUTH_SECRET_KEY,
        {
          algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
          expiresIn: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
          issuer: OauthHelper.getFullUrl(req),
          audience: client.clientId,
          subject: passwordGrantData.userId,
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

      /**
       * Create JWT token
       * **************************************
       */
      const token = jwt.sign(
        {
          client_id: client.clientId,
          scope: passwordGrantData.scope,
          azp: client.clientId,
        } as IJwtTokenPayload,
        oauthParams.OAUTH_SECRET_KEY,
        {
          algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
          expiresIn: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
          issuer: OauthHelper.getFullUrl(req),
          audience: client.clientId,
          subject: passwordGrantData.userId,
          jwtid: oauthAccessToken._id.toString(),
        }
      );

      return res.status(HttpStatus.Ok).json({
        access_token: token,
        token_type: oauthParams.OAUTH_TOKEN_TYPE,
        expires_in: oauthParams.OAUTH_ACCESS_TOKEN_EXPIRE_IN,
        refresh_token: refreshToken,
        data: passwordGrantData.extraData,
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

export default TokenGrantPasswordCredentialsHelper;
