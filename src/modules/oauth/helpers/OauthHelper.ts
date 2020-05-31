import { Request, Response } from "express";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import { sign } from "jsonwebtoken";
import UrlHelper from "./UrlHelper";
import HttpStatus from "../../../common/HttpStatus";
import IOauthError from "../interfaces/IOauthError";
import { IRequiredOauthContext } from "../OauthContext";

class OauthHelper {

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

  jwtSign(req: Request, oauthContext: IRequiredOauthContext, claims: IJwtTokenPayload) {
    return sign(claims, oauthContext.secretKey, {
      algorithm: oauthContext.jwtAlgorithm,
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
