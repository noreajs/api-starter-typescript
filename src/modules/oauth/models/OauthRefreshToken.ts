import { mongooseModel, Document, Schema } from "@noreajs/mongoose";

export interface IOauthRefreshToken extends Document {
  accessToken: string;
  revokedAt?: Date;
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
    revokedAt: {
      type: Schema.Types.Date,
    },
    expiresAt: {
      type: Schema.Types.Date,
    },
  }),
});
