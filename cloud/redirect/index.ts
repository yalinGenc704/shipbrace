/**
 * shipbrace.com and www.shipbrace.com, until there is a home page: send
 * everyone to the app. A temporary redirect (302), so browsers do not remember
 * it once the home page exists.
 */
export default {
  fetch(request: Request): Response {
    const url = new URL(request.url);
    return Response.redirect(`https://app.shipbrace.com${url.pathname === "/" ? "/" : url.pathname}${url.search}`, 302);
  },
};
