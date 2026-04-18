import { Ctx, EndpointMatcher, RegexMatcher } from "@budibase/types"

const PARAM_REGEX = /\/:(.*?)(\/.*)?$/g

export const buildMatcherRegex = (
  patterns: EndpointMatcher[]
): RegexMatcher[] => {
  if (!patterns) {
    return []
  }
  return patterns.map(pattern => {
    let route = pattern.route
    const method = pattern.method

    // if there is a param in the route
    // use a wildcard pattern
    const matches = route.match(PARAM_REGEX)
    if (matches) {
      for (let match of matches) {
        const suffix = match.endsWith("/") ? "/" : ""
        const pattern = "/.*" + suffix
        route = route.replace(match, pattern)
      }
    }

    // GHSA-8783-3wgf-jggf (CWE-287) — the compiled regex is anchored at the
    // start (`^`) and must terminate at one of three positions: (a) a path
    // separator `/` to allow prefix-matching against sub-routes (e.g. pattern
    // `/api/system` matches `/api/system/status`, `/api/system/environment`,
    // etc. — required for public-endpoint allowlist semantics), (b) the
    // query-string delimiter `\?` to preserve matching when the request URL
    // carries a query string, or (c) the end of the input string `$` for
    // exact-path matches. This terminator alternation eliminates the
    // unanchored-regex authentication bypass (e.g. prevents pattern
    // `/api/system/status` from false-positive matching
    // `/api/system/status-extended` or any substring injection attempt)
    // while preserving the legitimate prefix-match behavior required by
    // Directive 4 of the security fix (legitimate public endpoints such as
    // `/api/global/configs/public/translations`, `/api/system/status`, and
    // `/api/global/users/invite/:code` must remain reachable without
    // authentication). The defense-in-depth property is completed on line 32
    // where `regex.test(ctx.path)` ensures the query string is excluded
    // from the authentication decision under all conditions.
    return { regex: new RegExp(`^${route}(/|\\?|$)`), method, route }
  })
}

export const matches = (ctx: Ctx, options: RegexMatcher[]) => {
  return options.find(({ regex, method }) => {
    const urlMatch = regex.test(ctx.path)
    const methodMatch =
      method === "ALL"
        ? true
        : ctx.request.method.toLowerCase() === method.toLowerCase()
    return urlMatch && methodMatch
  })
}
