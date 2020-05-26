import IUser from "../interfaces/IUser";
import validator from "validator";
import { encrypt, verify } from "unixcrypt";
import { mongooseModel, Schema } from "@noreajs/mongoose";

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
        required: [true, "The secret code is required."],
      },
      admin: {
        type: Schema.Types.Boolean,
        required: false,
        default: false,
      },
      online: {
        type: Schema.Types.Boolean,
        required: false,
        default: false,
      },
      socketId: {
        type: Schema.Types.String,
        required: false,
      },
      locale: {
        type: Schema.Types.String,
        required: [true, "The locale is required."],
      },
      emailVerifiedAt: {
        type: Schema.Types.Date,
        required: false,
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
