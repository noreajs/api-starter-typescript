class UrlHelper {
  injectQueryParams(uri: string, params: any) {
    const uriObj = new URL(uri);
    for (const key in params) {
      if (params.hasOwnProperty(key)) {
        uriObj.searchParams.append(key, params[key]);
      }
    }
    return uriObj.toString();
  }
}

export default new UrlHelper();
