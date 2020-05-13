import { Request, Response } from "express";
import HttpStatus from "../../../common/HttpStatus";

class OauthController {
  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  async authorize(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      message: "Authorize",
    });
  }

  /**
   * Generate token
   * @param req request
   * @param res response
   */
  async token(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      message: "Token",
    });
  }

  /**
   * Purge expired and revoked token
   * @param req request
   * @param res response
   */
  async purge(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      message: "Purge",
    });
  }
}

export default new OauthController();
