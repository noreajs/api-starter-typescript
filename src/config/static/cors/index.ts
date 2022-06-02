/**
 * Allowed urls
 */
const allowedUrls: (string | RegExp)[] = ["*"];

// load urls from env
const ENV_CORS_ALLOWED_URLS = `${process.env.CORS_ALLOWED_URLS}`;
if (ENV_CORS_ALLOWED_URLS.length !== undefined) {
  const urls = ENV_CORS_ALLOWED_URLS.split(",");
  for (const url of urls) {
    allowedUrls.push(url);
  }
}
// console.log("allowed urls", allowedUrls);
// local environnement only
if (!process.env.NODE_ENV || process.env.DEBUG_MODE === "true") {
  allowedUrls.push(`http://localhost:${process.env.PORT ?? 8080}`);
  allowedUrls.push(`http://127.0.0.1:${process.env.PORT ?? 8080}`);
}

export default allowedUrls;
