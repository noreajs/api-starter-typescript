import crypto from "crypto";
import { Request } from "express";

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
    return req.protocol + '://' + req.get('host')
  }
}

export default new OauthHelper();
