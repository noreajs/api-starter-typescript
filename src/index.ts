import { NoreaApp } from "@noreajs/core";
import socketIo from "socket.io";
import bodyParser from "body-parser";
import cors from "cors";
import apiRoutes from "./routes/api.routes";
import socketIoServer from "./config/socket.io/socket.io.server";
import { MongoDBContext } from "@noreajs/mongoose";
import Oauth from "./modules/oauth/Oauth";
import User from "./models/User";
import IEndUserAuthData from "./modules/oauth/interfaces/IEndUserAuthData";
import { JwtTokenReservedClaimsType } from "./modules/oauth/interfaces/IJwt";

/**
 * Norea.Js app initialization
 */
const app = new NoreaApp(apiRoutes, {
  forceHttps: false,
  beforeStart: (app) => {
    // init cors
    app.use(cors());
    // support application/json type post data
    app.use(bodyParser.json());
    //support application/x-www-form-urlencoded post data
    app.use(bodyParser.urlencoded({ extended: false }));
    // Get MongoDB Instance
    MongoDBContext.init({
      connectionUrl: `${process.env.MONGODB_URI}`,
      onConnect: (connection) => {
        // Mongoose oauth 2  provider initialization
        new Oauth(app).init({
          providerName: "Oauth 2 Provider",
          jwtAlgorithm: "HS512",
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
app.start(3000);
