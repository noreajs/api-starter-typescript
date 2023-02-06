import { SocketIOServer } from "@noreajs/realtime";
import IUser from "../interfaces/IUser";

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

  export default socketIoServer