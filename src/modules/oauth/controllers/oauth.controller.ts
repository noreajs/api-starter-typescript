import { Request, Response } from "express";
import HttpStatus from "../../../common/HttpStatus";
import { IRequiredOauthContext } from "../OauthContext";

class OauthController {
  oauthContext: IRequiredOauthContext;

  constructor(oauthContext: IRequiredOauthContext) {
    this.oauthContext = oauthContext;
  }

  /**
   * Generate token
   * @param req request
   * @param res response
   */
  async callback(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      query: req.query,
      body: req.body,
    });
  }
}

export default OauthController;
