import apiRoutes from "./routes/api.routes";
import { MongoDBContext } from "@noreajs/mongoose";
import User from "./models/User";
import {
  Oauth,
  IEndUserAuthData,
  JwtTokenReservedClaimsType,
} from "@noreajs/oauth-v2-provider-me";
import { SocketIOServer } from "@noreajs/realtime";
import IUser from "./interfaces/IUser";
import session from "express-session";
import connectMongo from "connect-mongo";
import { NoreaBootstrap } from "@noreajs/core";
import { I18n } from "@noreajs/i18n";

const MongoDBStore = connectMongo(session);

/**
 * Socket.io server initialization
 *
 */
const socketIoServer = new SocketIOServer().namespace<IUser>({
  name: "/socket.io",
  middlewares: [
    async (socket, fn) => {
      console.log("Here is a global socket middleware!");

      // /**
      //  * Secure socket connection example
      //  */
      // await Oauth.verifyToken(
      //   socket.handshake.query.token,
      //   (userId, user) => {
      //     socket.user = user;
      //     fn();
      //   },
      //   (reason, authError) => {
      //     if (authError) {
      //       fn(reason);
      //     } else {
      //       fn();
      //     }
      //   }
      // );

      fn();
    },
  ],
  onConnect: (io, namespace, socket) => {
    console.log(`Namespace ${namespace.name}: Socket ${socket.id} connected`);
    if (socket.user)
      console.log(`Namespace ${namespace.name}: user ${socket.user} connected`);
  },
  onDisconnect: (io, namespace, socket, reason: any) => {
    console.log(
      `Namespace ${namespace.name}: Socket ${socket.id} disconnected`,
      reason
    );
  },
});

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
  appName: "Api Starter Typescript",
  secretKey:
    "66a5ddac054bfe9389e82dea96c85c2084d4b011c3d33e0681a7488756a00ca334a1468015da8",
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
  console.log("before init");
  /**
   * Get MongoDB Instance
   */
  await MongoDBContext.init({
    connectionUrl: `${process.env.MONGODB_URI}`,
    onConnect: (connection) => {
      api.updateInitConfig({
        sessionOptions: {
          store: new MongoDBStore({
            mongooseConnection: connection,
          }),
        },
      });
    },
  });
});

api.beforeStart(async (app) => {
  console.log("before start");
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
      console.log(sub);
      return await User.findById(sub);
    },
    // securityMiddlewares: [Oauth.authorize()],
  });
});

api.afterStart((app, server, port) => {
  console.log("after init");
  console.log(`Environement : ${process.env.NODE_ENV || "local"}`);
  console.log("Express server listening on port " + port);

  // initialize socket io on the server
  socketIoServer.attach(server);
});

/**
 * Start your app
 */
api.start();
