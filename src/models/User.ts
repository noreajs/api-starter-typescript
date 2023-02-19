import IUser from "../interfaces/IUser";
import validator from "validator";
import { encrypt, verify } from "unixcrypt";
import { mongooseModel } from "@noreajs/mongoose";
import { Schema } from "mongoose";

export default mongooseModel<IUser>({
  name: "User",
  collection: "users",
  schema: new Schema(
    {
      profilePicture: { type: String },
      username: {
        type: Schema.Types.String,
        required: [true, "Username is required."],
      },
      email: {
        type: Schema.Types.String,
        unique: true,
        required: true,
        validate: [
          {
            async validator(value: string): Promise<boolean> {
              return validator.isEmail(value);
            },
            msg: `The email is not valid.`,
          },
        ],
      },
      password: {
        type: Schema.Types.String,
      },
      admin: {
        type: Schema.Types.Boolean,
        default: false,
      },
      online: {
        type: Schema.Types.Boolean,
        default: false,
      },
      socketId: {
        type: [Schema.Types.String],
        default: []
      },
      locale: {
        type: Schema.Types.String,
        default: 'en-EN'
      },
      emailVerifiedAt: {
        type: Schema.Types.Date,
      },
      provider: {
        type: Schema.Types.String,
        enum: ["email", "github"],
        default: "email"
      },
      providerUserId: {
        type: Schema.Types.String,
      },
      deletedAt: {
        type: Date,
      },
      lockedAt: {
        type: Date,
      },
    },
    {
      timestamps: true,
    }
  ),

  externalConfig: (schema: Schema<any>) => {
    schema.methods = {
      /**
       * Encrypt and set secret code
       * @param password user secret code
       */
      setPassword(password: string) {
        // load current user
        const self = this as IUser;
        // Hashing user's salt and secret code with 1000 iterations, and sha512 digest
        self.password = encrypt(password, `$5`);
      },

      /**
       * Check secret code validity
       * @param password user secret code
       */
      verifyPassword(password: string): boolean {
        // load current user
        const self = this as IUser;
        return verify(password, self.password);
      },
    };
  },
});
