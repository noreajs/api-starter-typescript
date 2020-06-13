import { NoreaApp } from "@noreajs/core";
import socketIo from "socket.io";
import apiRoutes from "./routes/api.routes";
import socketIoServer from "./config/socket.io/socket.io.server";
import { MongoDBContext } from "@noreajs/mongoose";
import User from "./models/User";
import {
  Oauth,
  IEndUserAuthData,
  JwtTokenReservedClaimsType,
} from "@noreajs/oauth-v2-provider-mongoose";

/**
 * Norea.Js app initialization
 */
const app = new NoreaApp(apiRoutes, {
  beforeStart: (app) => {
    // Get MongoDB Instance
    MongoDBContext.init({
      connectionUrl: `${process.env.MONGODB_URI}`,
      onConnect: (connection) => {
        // Mongoose oauth 2 provider initialization
        Oauth.init(app, {
          providerName: "Oauth 2 Provider",
          secretKey:
            "66a5ddac054bfe9389e82dea96c85c2084d4b011c3d33e0681a7488756a00ca334a1468015da8",
          authenticationLogic: async function (
            username: string,
            password: string
          ) {
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
                  user.emailVerifiedAt !== undefined &&
                  user.emailVerifiedAt !== null,
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
          securityMiddlewares: [Oauth.authorize()],
        });
      },
    });
    // set the view engine to ejs
    app.set("view engine", "ejs");
  },
  afterStart: (app, server, port) => {
    console.log(`Environement : ${process.env.NODE_ENV || "local"}`);
    console.log("Express server listening on port " + port);

    // initialize socket io on the server
    const io: socketIo.Server = socketIo(server);

    // listening socket.io connections
    socketIoServer.listenConnection(io);
  },
});

/**
 * Start your app
 */
app.start();
