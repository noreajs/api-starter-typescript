import crypto from "crypto";
import { Request } from "express";
import { IOauthDefaults } from "../OauthDefaults";
import IJwtTokenPayload from "../interfaces/IJwtTokenPayload";
import { SignOptions, sign } from "jsonwebtoken";
import { IOauthClient } from "../models/OauthClient";

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

  getFullUrl(req: Request) {
    return req.protocol + "://" + req.get("host");
  }

  jwtSign(req: Request, oauthParams: IOauthDefaults, claims: IJwtTokenPayload) {
    return sign(claims, oauthParams.OAUTH_SECRET_KEY, {
      algorithm: oauthParams.OAUTH_JWT_ALGORITHM,
      issuer: this.getFullUrl(req),
    });
  }

  getMatchedScope(queryScope: string, targetScope: string) {
    const queryScopes = queryScope.split(" ");
    const targetScopes = targetScope.split(" ");
    const matches = [];
    for (const scope of queryScopes) {
      if (targetScopes.includes(scope)) {
        matches.push(scope);
      }
    }
    return matches.join(" ");
  }
}

export default new OauthHelper();
