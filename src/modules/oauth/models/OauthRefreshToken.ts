import { mongooseModel, Document, Schema } from "@noreajs/mongoose";

export interface IOauthRefreshToken extends Document {
  token: string;
  revokedAt?: Date;
  expiresAt?: Date;
}

export default mongooseModel<IOauthRefreshToken>({
  name: "OauthRefreshToken",
  collection: "oauth_refresh_tokens",
  schema: new Schema({
    token: {
      type: Schema.Types.String,
      required: [true, "The token is required."],
    },
    revokedAt: {
      type: Schema.Types.Date,
    },
    expiresAt: {
      type: Schema.Types.Date,
    },
  }),
});
