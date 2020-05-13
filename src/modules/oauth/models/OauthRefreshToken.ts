import { Document, Schema } from "mongoose";
import mongooseModel from "../../../core/mongoose/MongooseModel";

export interface IOauthRefreshToken extends Document {
  accessToken: string;
  revoked: boolean;
  expiresAt?: Date;
}

export default mongooseModel<IOauthRefreshToken>({
  name: "OauthRefreshToken",
  collection: "oauth_refresh_tokens",
  schema: new Schema({
    accessToken: {
      type: Schema.Types.String,
      required: [true, "The access token is required."],
    },
    revoked: {
      type: Schema.Types.Boolean,
    },
    expiresAt: {
      type: Schema.Types.Date,
    },
  }),
});
