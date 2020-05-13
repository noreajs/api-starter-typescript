import { Document, Schema } from "mongoose";
import { IOauthClient } from "./OauthClient";
import mongooseModel from "../../../core/mongoose/MongooseModel";

export interface IOauthAuthCode extends Document {
  userId: any;
  client: IOauthClient;
  scopes: string;
  revoked: boolean;
  expiresAt: Date;
}

export default mongooseModel<IOauthAuthCode>({
  name: "OauthAuthCode",
  collection: "oauth_auth_codes",
  schema: new Schema({
    userId: {
      type: Schema.Types.String,
      required: [true, "The user id is required."]
    },
    client: {
      type: Schema.Types.ObjectId,
      ref: "OauthClient",
      required: [true, "The oauth client is required."],
    },
    scopes: {
      type: Schema.Types.String,
    },
    revoked: {
      type: Schema.Types.Boolean,
      required: [true, 'Revoke state is required.']
    },
    expiresAt: {
      type: Schema.Types.Date,
    },
  }),
});
