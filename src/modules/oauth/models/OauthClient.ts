import mongooseModel from "../../../core/mongoose/MongooseModel";
import { Document, Schema } from "mongoose";
import validator from "validator";

export interface IOauthClient extends Document {
  userId: String;
  name: String;
  secret: String;
  provider: String;
  redirect: String;
  personalAccessClient: String;
  passwordClient: boolean;
  revoked: boolean;
  approvedAt: Date;
}

export default mongooseModel<IOauthClient>({
  name: "OauthClient",
  collection: "oauth_clients",
  schema: new Schema(
    {
      userId: {
        type: Schema.Types.String,
      },
      name: {
        type: Schema.Types.String,
        unique: true,
        required: [true, "The name is required"],
      },
      secret: {
        type: Schema.Types.String,
        maxlength: 100,
      },
      provider: {
        type: Schema.Types.String,
      },
      redirect: {
        type: Schema.Types.String,
        validate: [
          {
            validator: (value: string) => {
              return validator.isURL(value);
            },
            message: "The redirect value must be a valid URL.",
          },
        ],
      },
      personalAccessClient: {
        type: Schema.Types.Boolean,
      },
      passwordClient: {
        type: Schema.Types.Boolean,
      },
      revoked: {
        type: Schema.Types.Boolean,
        required: [true, "Revoke state is required."],
      },
      approvedAt: {
        type: Schema.Types.Date,
      },
    },
    {
      timestamps: true, // automatically add createdAt and updatedAt (discover)
    }
  ),
});
