import { IOauthClient } from "./OauthClient";
import { mongooseModel, Document, Schema, model } from "@noreajs/mongoose";

export interface IOauthAccessToken extends Document {
  userId: string;
  client: IOauthClient;
  name: string;
  scope: string;
  userAgent: string;
  revokedAt?: Date;
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
      },
      client: {
        type: Schema.Types.ObjectId,
        ref: "OauthClient",
        autopopulate: true,
      },
      name: {
        type: Schema.Types.String,
      },
      scope: {
        type: Schema.Types.String,
      },
      userAgent: {
        type: Schema.Types.String,
      },
      revokedAt: {
        type: Schema.Types.Date,
      },
      expiresAt: {
        type: Schema.Types.Date,
      },
    },
    {
      timestamps: true,
    }
  )
});
