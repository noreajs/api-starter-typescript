import { IEndUserAuthData, OauthStrategy } from "@noreajs/oauth-v2-provider-me";
import Axios, { AxiosResponse } from "axios";
import { AnyKeys } from "mongoose";
import OauthClient from "oauth-v2-client";
import IGithubUser from "../../../interfaces/github/IGithubUser";
import IGithubUserEmail from "../../../interfaces/github/IGithubUserEmail";
import IUser from "../../../interfaces/IUser";
import User from "../../../models/User";

const github = new OauthClient({
  oauthOptions: {
    clientId: `${process.env.GITHUB_OAUTH_APP_CLIENT_ID}`,
    clientSecret: `${process.env.GITHUB_OAUTH_APP_CLIENT_SECRET}`,
    accessTokenUrl: "https://github.com/login/oauth/access_token",
    authUrl: "https://github.com/login/oauth/authorize",
    apiBaseURL: "https://api.github.com",
    scopes: ["user"],
    callbackUrl: `http://localhost:8080/oauth/v2/strategy/callback/github`
  },
  requestOptions: {
    headers: {
      Accept: "application/json",
    },
  },
  log: true,
});

const githubOauthStrategy = new OauthStrategy({
  client: github,
  grant: "authorization_code",
  identifier: "github",
  providerName: "Github",
  userLookup: async (client: OauthClient, token) => {
    return new Promise(async (resolve, reject) => {
      await Axios.create(
        client.authorizationCode.sign({
          token,
          headers: {
            Accept: "application/vnd.github+json",
          },
        })
      )
        .get("/user")
        .then(async (userResponse: AxiosResponse<IGithubUser>) => {
          // load github user
          const githubUser = userResponse.data;

          const responseEmails = await Axios.create(
            client.authorizationCode.sign({
              token,
              headers: {
                Accept: "application/vnd.github+json",
              },
            })
          )
            .get<IGithubUserEmail[]>("/user/emails")

          const primaryEmail = responseEmails.data.find(item => item.primary)

          // load existing user
          const user = await User.findOne<IUser>({
            providerUserId: githubUser.id,
            provider: "github"
          });

          // user exist
          if (user) {
            resolve({
              scope: "*",
              userId: user._id,
              extraData: user,
            } as IEndUserAuthData);
          } else {
            // the user has a primary email
            if (primaryEmail) {
              // create the user if he does not exists
              const user: IUser = await User.create<AnyKeys<IUser>>({
                username: githubUser.name,
                email: primaryEmail.email,
                providerUserId: githubUser.id,
                provider: "github",
                emailVerifiedAt: primaryEmail.verified ? new Date() : undefined
              })

              resolve({
                scope: "*",
                userId: user._id,
                extraData: user,
              } as IEndUserAuthData);
            } else {
              resolve(undefined);
            }
          }
        })
        .catch((error) => {
          resolve(undefined);
        });
    });
  },
});

export { githubOauthStrategy };

export default github;
// https://docs.github.com/en/free-pro-team@latest/developers/webhooks-and-events/about-webhooks
