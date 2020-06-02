import { Application, Request, Response, NextFunction } from "express";
import { IOauthContext } from "./interfaces/IOauthContext";
import oauthRoutes from "./routes/oauth.routes";
import OauthContext from "./OauthContext";
import jwt from "jsonwebtoken";
import { IJwtTokenPayload } from "./interfaces/IJwt";
import HttpStatus from "../../common/HttpStatus";
import OauthAccessToken from "./models/OauthAccessToken";

class Oauth {
  static context?: OauthContext;
  app: Application;

  constructor(app: Application) {
    this.app = app;
  }

  /**
   * Initialize oauth 2 module
   * @param context oauth 2 context
   */
  init(initContext: IOauthContext) {
    // create context
    Oauth.context = new OauthContext(initContext);
    // Add oauth routes
    oauthRoutes(this.app, Oauth.context);
  }

  static authorize(scope?: string) {
    if (Oauth.context) {
      // get oauth context
      const oauthContext = Oauth.context;
      return async (req: Request, res: Response, next: NextFunction) => {
        // authorization server
        const authorization =
          req.headers["authorization"] ?? req.headers["proxy-authorization"];
        // authorization required
        if (authorization) {
          // bearer token required
          if (authorization.startsWith(oauthContext.tokenType)) {
            // token parts
            const parts = authorization.split(" ");
            try {
              // Verify token signature
              const tokenData = jwt.verify(parts[1], oauthContext.secretKey, {
                algorithms: [oauthContext.jwtAlgorithm],
              }) as IJwtTokenPayload;

              // load access token
              const accessToken = await OauthAccessToken.findById(
                tokenData.jti
              );

              // access token must exist localy
              if (accessToken) {
                // revocation state
                if (accessToken.revokedAt) {
                  return res.status(HttpStatus.Unauthorized).json({
                    message: "Access Token not approved",
                  });
                } else {
                  // scope validation if exist
                  if (scope) {
                    const tokenScope = tokenData.scope ?? accessToken.scope;
                    const tokenScopeParts = tokenScope.split(" ");
                    const scopeParts = scope.split(" ");
                    for (const item of tokenScopeParts) {
                      if (!scopeParts.includes(item)) {
                        return res.status(HttpStatus.Unauthorized).json({
                          message: "Insufficient scope",
                        });
                      }
                    }

                    // lookup sub
                    if (oauthContext.subLookup) {
                      res.locals.user = await oauthContext.subLookup(
                        accessToken.userId
                      );
                    }

                    // the user can access to the resource
                    next();
                  } else {
                    // the user can access to the resource
                    next();
                  }
                }
              } else {
                return res.status(HttpStatus.Unauthorized).json({
                  message: "Invalid access token",
                });
              }
            } catch (error) {
              return res.status(HttpStatus.Unauthorized).json({
                message: "Access Token expired",
              });
            }
          } else {
            return res.status(HttpStatus.Unauthorized).json({
              message: `${oauthContext.tokenType} Token type required`,
            });
          }
        } else {
          return res.status(HttpStatus.Unauthorized).json({
            message: `Authorization Header Required`,
          });
        }
      };
    } else {
      return async (req: Request, res: Response, next: NextFunction) => {
        console.warn(
          "The Oauth.context static property is not defined. Make sure you have initialized the Oauth package as described in the documentation."
        );
        next();
      };
    }
  }
}

export default Oauth;
