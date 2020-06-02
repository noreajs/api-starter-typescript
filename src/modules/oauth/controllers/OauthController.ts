import OauthContext from "../OauthContext";

export default class OauthController {
  oauthContext: OauthContext;

  constructor(oauthContext: OauthContext) {
    this.oauthContext = oauthContext;
  }
}
