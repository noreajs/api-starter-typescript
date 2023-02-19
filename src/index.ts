import { NoreaBootstrap } from "@noreajs/core";
import { I18n } from "@noreajs/i18n";
import { MongoDBContext } from "@noreajs/mongoose";
import {
  IEndUserAuthData,
  JwtTokenReservedClaimsType, Oauth
} from "@noreajs/oauth-v2-provider-me";
import connectMongo from "connect-mongo";
import { githubOauthStrategy } from "./config/static/oauth/github.oauth-provider";
import User from "./models/User";
import apiRoutes from "./routes/api.routes";
import socketIoServer from "./services/socketIoServer";

// const MongoDBStore = connectMongo(session);

/**
 * I18n settings
 */
const i18n = new I18n({
  locales: ["en-US", "fr-FR"],
  fallback: "fr-fr",
});

/**
 * Create Norea.js application
 */
const api = new NoreaBootstrap(apiRoutes, {
  appName: process.env.APP_NAME ?? "Noreajs Starter API",
  secretKey: process.env.APP_SECRET_KEY,
  helmetConfig: {
    contentSecurityPolicy: {
      directives: {
        frameAncestors: ["codesandbox.io"],
        reportUri: "/csp-report-violation",
      },
    },
  },
});

api.beforeInit(async (app) => {
  /**
   * Get MongoDB Instance
   */
  await MongoDBContext.init({
    connectionUrl: `${process.env.MONGODB_URI}`,
    onConnect: (connection) => {
      api.updateInitConfig({
        sessionOptions: {
          store: connectMongo.create({
            client: connection.getClient() as any,
          }),
        },
      });
    },
  });
});

api.beforeStart(async (app) => {
  // inject socket.io server to every request
  app.use((req, res, next) => {
    // set socket.io server
    res.locals.socketServer = socketIoServer.getServer();
    // continue the request
    next();
  });

  // inject i18n
  app.use((req, res, next) => {
    // set i18n object
    res.locals.i18n = i18n;
    // continue the request
    next();
  });

  // Mongoose oauth 2 provider initialization
  await Oauth.init(app, {
    providerName: app.appName,
    secretKey: app.secretKey,
    authenticationLogic: async function (username: string, password: string) {
      const user = await User.findOne({ email: username });
      if (user) {
        if (user.verifyPassword(password)) {
          const data: IEndUserAuthData = {
            scope: "*",
            userId: user._id,
            extraData: {
              user: user,
            },
          };
          return data;
        } else {
          return undefined;
        }
      } else {
        return undefined;
      }
    },
    supportedOpenIdStandardClaims: async function (userId: string) {
      const user = await User.findById(userId);
      if (user) {
        return {
          name: user.username,
          email: user.email,
          email_verified:
            user.emailVerifiedAt !== undefined && user.emailVerifiedAt !== null,
          updated_at: user.updatedAt.getTime(),
        } as JwtTokenReservedClaimsType;
      } else {
        return undefined;
      }
    },
    subLookup: async (sub: string) => {
      return await User.findById(sub);
    },
    // securityMiddlewares: [Oauth.authorize()],
    strategies: [githubOauthStrategy],
  });
});

api.afterStart(async (app, server, port) => {
  // initialize socket io on the server
  socketIoServer.attach(server);

  // reset all user session data
  await User.updateMany({}, {
    $set: {
      socketId: []
    }
  })
});

/**
 * Start your app
 */
api.start();
