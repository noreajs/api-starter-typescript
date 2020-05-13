import { Document, Schema } from "mongoose";
import { IOauthClient } from "./OauthClient";
import mongooseModel from "../../../core/mongoose/MongooseModel";

export interface IOauthAccessToken extends Document {
  userId: any;
  client: IOauthClient;
  name: string;
  scopes: string;
  revoked: boolean;
  expiresAt?: Date;
}

export default mongooseModel<IOauthAccessToken>({
  name: "OauthAccessToken",
  collection: "oauth_access_tokens",
  autopopulate: true,
  schema: new Schema(
    {
      userId: {
        type: Schema.Types.String,
        autopopulate: true,
      },
      client: {
        type: Schema.Types.ObjectId,
        ref: "OauthClient",
        autopopulate: true,
      },
      name: {
        type: Schema.Types.String,
      },
      scopes: {
        type: Schema.Types.String,
      },
      revoked: {
        type: Schema.Types.Boolean,
        required: [true, "Revoke state is required."],
      },
      expiresAt: {
        type: Schema.Types.Date,
      },
    },
    {
      timestamps: true,
    }
  ),
});
