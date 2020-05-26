import { mongooseModel, Document, Schema } from "@noreajs/mongoose";
import validator from "validator";

export type OauthClientTypes = "confidential" | "public";
export type OauthClientProfiles = "web" | "user-agent-based" | "native";

export interface IOauthClient extends Document {
  clientId: string;
  name: string;
  website?: string;
  logo?: string;
  description?: string;
  legalTermsAcceptedAt?: Date;
  secretKey: string;
  redirectURIs: string[];
  clientType: OauthClientTypes;
  clientProfile: OauthClientProfiles;
  programmingLanguage: string;
  scope: string;
  personalAccessClient: string;
  passwordClient: boolean;
  revokedAt?: Date;
}

export default mongooseModel<IOauthClient>({
  name: "OauthClient",
  collection: "oauth_clients",
  schema: new Schema(
    {
      clientId: {
        type: Schema.Types.String,
        unique: true,
      },
      name: {
        type: Schema.Types.String,
        unique: true,
        required: [true, "The name is required"],
      },
      website: {
        type: Schema.Types.String,
        validate: [
          {
            validator: (value: string) => {
              return !value || validator.isURL(value);
            },
            message: "The website value must be a valid URL.",
          },
        ],
      },
      logo: {
        type: Schema.Types.String,
        validate: [
          {
            validator: (value: string) => {
              return !value || validator.isURL(value);
            },
            message: "The log value must be a valid URL.",
          },
        ],
      },
      programmingLanguage: {
        type: Schema.Types.String,
      },
      description: {
        type: Schema.Types.String,
      },
      legalTermsAcceptedAt: {
        type: Schema.Types.Date,
      },
      secretKey: {
        type: Schema.Types.String,
      },
      redirectURIs: [Schema.Types.String],
      clientType: {
        type: Schema.Types.String,
        enum: ["confidential", "public"],
        default: "public",
      },
      clientProfile: {
        type: Schema.Types.String,
        enum: ["web", "user-agent-based", "native"],
        required: [true, "The client profile is required."],
      },
      scope: {
        type: Schema.Types.String,
      },
      personalAccessClient: {
        type: Schema.Types.Boolean,
      },
      passwordClient: {
        type: Schema.Types.Boolean,
      },
      revokedAt: {
        type: Schema.Types.Date,
      },
    },
    {
      timestamps: true, // automatically add createdAt and updatedAt (discover)
    }
  ),
  externalConfig: function (sc: Schema) {
    // before save
    sc.pre<IOauthClient>("save", function () {
      if (this.clientProfile === "web") {
        this.clientType = "confidential";
      } else {
        this.clientType = "public";
      }

      /**
       * Validate redirect URIs
       */
      let invalidUriFound = false;
      for (const uri of this.redirectURIs) {
        if (!validator.isURL(uri)) {
          invalidUriFound = true;
          break;
        }
      }
      if (invalidUriFound) {
        throw {
          message: "The redirect URIs value must be valid URLs.",
        };
      }
    });
  },
});
