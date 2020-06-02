import { Request, Response } from "express";
import HttpStatus from "../../../common/HttpStatus";
import OauthContext from "../OauthContext";

class OauthController {
  oauthContext: OauthContext;

  constructor(oauthContext: OauthContext) {
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
