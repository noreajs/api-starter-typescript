import { Request, Response } from "express";
import HttpStatus from "../../../common/HttpStatus";
import OauthDefaults, { IOauthDefaults } from "../OauthDefaults";

class OauthController {
  oauthParams: IOauthDefaults;

  constructor() {
    this.oauthParams = OauthDefaults;
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

export default new OauthController();
