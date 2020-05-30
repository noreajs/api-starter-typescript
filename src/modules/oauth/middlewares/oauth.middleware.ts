import { Request, Response, NextFunction } from "express";

class OauthMiddleware {
  /**
   * Authorization request validation required
   * @param req request
   * @param res response
   * @param next next function
   */
  async authorize(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    
  }
}

export default new OauthMiddleware();
