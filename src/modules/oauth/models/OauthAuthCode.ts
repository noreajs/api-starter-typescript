import { IOauthClient } from "./OauthClient";
import { mongooseModel, Document, Schema } from "@noreajs/mongoose";

export interface IOauthAuthCode extends Document {
  authorizationCode: string;
  client: IOauthClient;
  scope: string;
  revokedAt: Date;
  expiresAt: Date;
}

export default mongooseModel<IOauthAuthCode>({
  name: "OauthAuthCode",
  collection: "oauth_auth_codes",
  schema: new Schema({
    authorizationCode: {
      type: Schema.Types.String,
      required: [true, "Authorization code is required."],
    },
    client: {
      type: Schema.Types.ObjectId,
      ref: "OauthClient",
      required: [true, "The oauth client is required."],
    },
    scope: {
      type: Schema.Types.String,
    },
    code_challenge: {
      type: Schema.Types.String,
    },
    revokedAt: {
      type: Schema.Types.Date,
    },
    expiresAt: {
      type: Schema.Types.Date,
    },
  }),
});
