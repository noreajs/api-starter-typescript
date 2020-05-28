import { mongooseModel, Document, Schema } from "@noreajs/mongoose";
import { IOauthAccessToken } from "./OauthAccessToken";

export interface IOauthRefreshTokenAttempt {
  ip: any;
  userAgent?: string;
  attemptedAt: Date;
}

export interface IOauthRefreshToken extends Document {
  accessToken: IOauthAccessToken;
  attemps: IOauthRefreshTokenAttempt[];
  revokedAt?: Date;
  expiresAt: Date;
}

export default mongooseModel<IOauthRefreshToken>({
  name: "OauthRefreshToken",
  collection: "oauth_refresh_tokens",
  schema: new Schema(
    {
      accessToken: {
        type: Schema.Types.ObjectId,
        ref: "OauthAccessToken",
        autopopulate: true,
        required: [true, "The access token is required."],
      },
      attemps: [Schema.Types.Mixed],
      revokedAt: {
        type: Schema.Types.Date,
      },
      expiresAt: {
        type: Schema.Types.Date,
        required: [true, "The refresh token expiration date is required."],
      },
    },
    {
      timestamps: true,
    }
  ),
});
