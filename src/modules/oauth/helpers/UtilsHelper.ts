import OauthHelper from "./OauthHelper";
import { Request } from "express";
import HttpStatus from "../../../common/HttpStatus";

class UtilsHelper {
  /**
   * Check required keys
   * @param attrs object attributes
   * @param target object
   */
  checkAttributes<T, K = keyof T>(attrs: K[], target: T):K[] {
    const r:K[] = [];
    for (const attr of attrs) {
      if (!(target as any)[attr]) {
        r.push(attr);
      }
    }
    return r;
  }
}

export default new UtilsHelper();
