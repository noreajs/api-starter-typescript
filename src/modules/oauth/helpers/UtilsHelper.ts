import OauthHelper from "./OauthHelper";
import { Request } from "express";
import HttpStatus from "../../../common/HttpStatus";

class UtilsHelper {
  /**
   * Check required keys
   * @param attrs object attributes
   * @param target object
   */
  checkAttributes<T, K = keyof T>(attrs: K[], target: T): K[] {
    const r: K[] = [];
    for (const attr of attrs) {
      const element = (target as any)[attr];
      if (!element || (typeof element === "string" && element.length === 0)) {
        r.push(attr);
      }
    }
    return r;
  }

  /**
   * Get scopes both in the two scopes
   * @param queryScope query scope
   * @param targetScope target scope
   */
  getMatchedScope(queryScope: string, targetScope: string) {
    const queryScopes = queryScope.split(" ");
    const targetScopes = targetScope.split(" ");
    const matches = [];
    for (const scope of queryScopes) {
      if (targetScopes.includes(scope)) {
        matches.push(scope);
      }
    }
    return matches.join(" ");
  }
}

export default new UtilsHelper();
