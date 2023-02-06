import socketIo from 'socket.io';
import jwt from "jsonwebtoken";
import User from '../../../models/User';
import IJWTData from '../../../interfaces/IJWTData';
import IUser from '../../../interfaces/IUser';


/**
 * Mark user as connected
 * 
 * @param socket socket connection
 */
export const connectuser = async (io: socketIo.Server, socket: socketIo.Socket) => {
    try {
        // get token from headers
        let accesstoken = socket.handshake.query.token as string;

        // extract credentials
        const jwtCredentials = jwt.verify(accesstoken, `${process.env.JWT_SECRET_KEY}`) as IJWTData;

        // load user
        const user = await User.findOne<IUser>({ email: jwtCredentials.sub });

        if (user) {
            // set changes
            user.online = true;

            // update online data
            await user.updateOne({
                $set: {
                    online: true,

                }, $push: {
                    socketId: socket.id
                }
            })
        }
    } catch (error) {
        // something bad happened
    }
}

/**
 * Mark user as disconnected
 * 
 * @param io socket io server
 * @param socket socket connection
 */
export const disconnectUser = async (io: socketIo.Server, socket: socketIo.Socket) => {
    // load related user
    const user = await User.findOne<IUser>({ socketId: socket.id });

    // check if user exist
    if (user) {
        // set changes
        user.online = false;

        const newSocketIds = user.socketId.filter(s => s === socket.id)

        // update online data
        await user.updateOne({
            $set: {
                online: newSocketIds.length !== 0,
                socketId: newSocketIds
            }
        });
    }
}