import crypto from "crypto";
import { Request, Response } from "express";
import { IOauthDefaults } from "../OauthDefaults";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import { sign } from "jsonwebtoken";
import UrlHelper from "./UrlHelper";
import HttpStatus from "../../../common/HttpStatus";
import IOauthError from "../interfaces/IOauthError";

class OauthHelper {
  /**
   * Verify the client secret
   * @param params params
   */
  verifyClientSecret(params: {
    clientId: string;
    hash: string;
    oauthSecretKey: string;
    oauthHmacAlgorithm: string;
  }) {
    const signature = crypto
      .createHmac(params.oauthHmacAlgorithm, params.oauthSecretKey)
      .update(params.clientId)
      .digest("hex");
    return signature === params.hash;
  }

  getBasicAuthHeaderCredentials(
    request: Request
  ):
    | {
        client_id: string;
        client_secret: string;
      }
    | undefined {
    const authorization = request.headers["authorization"];
    if (!authorization) {
      return undefined;
    } else {
      const base64Key = authorization.replace("Basic ", "");
      const credentials = Buffer.from(base64Key, "base64")
        .toString()
        .split(":");
      return {
        client_id: credentials[0],
        client_secret: credentials[1],
      };
    }
  }

  jwtSign(req: Request, oauthParams: IOauthDefaults, claims: IJwtTokenPayload) {
    return sign(claims, oauthParams.OAUTH_SECRET_KEY, {
      algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
      issuer: UrlHelper.getFullUrl(req),
    });
  }

  throwError(
    res: Response,
    error: IOauthError,
    redirectUri?: string
  ) {
    // 400 Bad Request status by default
    let status:number = HttpStatus.BadRequest;

    // special status
    switch(error.error){
      case "invalid_client":
        status = HttpStatus.Unauthorized;
        break;
    }

    /**
     * Redirect if needed
     */
    if (redirectUri) {
      return res.redirect(UrlHelper.injectQueryParams(redirectUri, error));
    } else {
      return res.status(status).json(error);
    }
  }
}

export default new OauthHelper();
