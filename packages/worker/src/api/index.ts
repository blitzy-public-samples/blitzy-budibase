import Router from "@koa/router"

const compress = require("koa-compress")

import zlib from "zlib"
import { routes } from "./routes"
import { middleware as pro } from "@budibase/pro"
import { auth, middleware } from "@budibase/backend-core"

const PUBLIC_ENDPOINTS = [
  // deprecated single tenant sso callback
  {
    route: "/api/admin/auth/google/callback",
    method: "GET",
  },
  // deprecated single tenant sso callback
  {
    route: "/api/admin/auth/oidc/callback",
    method: "GET",
  },
  {
    // this covers all of the POST auth routes
    route: "/api/global/auth/:tenantId",
    method: "POST",
  },
  {
    // this covers all of the GET auth routes
    route: "/api/global/auth/:tenantId",
    method: "GET",
  },
  {
    // this covers all of the public config routes
    route: "/api/global/configs/public",
    method: "GET",
  },
  {
    // Companion to the `/api/global/configs/public` entry above: the
    // anchored-regex fix for GHSA-8783-3wgf-jggf in
    // `packages/backend-core/src/middleware/matchers.ts` caused the
    // bare `/public` pattern to match only `/api/global/configs/public`
    // exactly, breaking public access to sub-routes such as
    // `/public/oidc` and `/public/translations`. The :subPath wildcard
    // parameter compiles (via PARAM_REGEX) to `/.*`, restoring the
    // original prefix-matching intent captured by the comment above.
    route: "/api/global/configs/public/:subPath",
    method: "GET",
  },
  {
    route: "/api/global/configs/checklist",
    method: "GET",
  },
  {
    route: "/api/global/users/init",
    method: "POST",
  },
  {
    route: "/api/global/users/invite/accept",
    method: "POST",
  },
  {
    route: "/api/system/environment",
    method: "GET",
  },
  {
    route: "/api/system/status",
    method: "GET",
  },
  // TODO: This should be an internal api
  {
    route: "/api/global/users/tenant/:id",
    method: "GET",
  },
  // TODO: This should be an internal api
  {
    route: "/api/system/restored",
    method: "POST",
  },
  {
    route: "/api/global/users/invite",
    method: "GET",
  },
  {
    // Companion to the `/api/global/users/invite` entry above: the
    // anchored-regex fix for GHSA-8783-3wgf-jggf in
    // `packages/backend-core/src/middleware/matchers.ts` caused the
    // bare `/invite` pattern to match only `/api/global/users/invite`
    // exactly, breaking the unauthenticated invite verification
    // endpoint `GET /api/global/users/invite/:code` (handled by
    // `controller.checkInvite`) which email recipients hit when
    // opening an invite link before creating their password. The
    // :code wildcard parameter compiles (via PARAM_REGEX) to `/.*`,
    // restoring the original prefix-matching intent.
    route: "/api/global/users/invite/:code",
    method: "GET",
  },
]

const ALLOW_INACTIVE_TENANT_ENDPOINTS = [
  {
    route: "/api/system/tenants/:tenantId",
    method: "DELETE",
  },
]

const NO_TENANCY_ENDPOINTS = [
  // system endpoints are not specific to any tenant
  // NOTE: :subPath is a wildcard parameter required so buildMatcherRegex
  // produces a prefix-matching regex (`^/api/system/.*(\?|$)`) for all
  // `/api/system/*` sub-routes (status, environment, accounts/:id/metadata,
  // logs, tenants/:id, restored). Without the :subPath parameter, the
  // anchored-regex fix for GHSA-8783-3wgf-jggf in
  // `packages/backend-core/src/middleware/matchers.ts` would cause this
  // entry to match only the exact path `/api/system`, breaking tenancy
  // bypass for every registered sub-route.
  {
    route: "/api/system/:subPath",
    method: "ALL",
  },
  // tenant is determined in request body
  // used for creating the tenant
  {
    route: "/api/global/users/init",
    method: "POST",
  },
  // tenant is retrieved from the user found by the requested email
  {
    route: "/api/global/users/sso",
    method: "POST",
  },
  // deprecated single tenant sso callback
  {
    route: "/api/admin/auth/google/callback",
    method: "GET",
  },
  // deprecated single tenant sso callback
  {
    route: "/api/admin/auth/oidc/callback",
    method: "GET",
  },
  // global user search - no tenancy
  // :id is user id
  // TODO: this should really be `/api/system/users/:id`
  {
    route: "/api/global/users/tenant/:id",
    method: "GET",
  },
  // tenant is determined from code in redis
  {
    route: "/api/global/users/invite/accept",
    method: "POST",
  },
  {
    route: "/api/global/users/invite/:code",
    method: "GET",
  },
  {
    route: "/api/global/users/accountholder",
    method: "GET",
  },
  {
    route: "/api/global/users/tenant/owner",
    method: "PUT",
  },
]

// most public endpoints are gets, but some are posts
// add them all to be safe
const NO_CSRF_ENDPOINTS = [...PUBLIC_ENDPOINTS]

const router: Router = new Router()

router
  .use(middleware.errorHandling)
  .use(middleware.featureFlagCookie)
  .use(
    compress({
      threshold: 2048,
      gzip: {
        flush: zlib.constants.Z_SYNC_FLUSH,
      },
      deflate: {
        flush: zlib.constants.Z_SYNC_FLUSH,
      },
      br: false,
    })
  )
  .use("/health", ctx => (ctx.status = 200))
  .use(auth.buildAuthMiddleware(PUBLIC_ENDPOINTS))
  .use(auth.buildTenancyMiddleware(PUBLIC_ENDPOINTS, NO_TENANCY_ENDPOINTS))
  .use(middleware.activeTenant(ALLOW_INACTIVE_TENANT_ENDPOINTS))
  .use(auth.buildCsrfMiddleware({ noCsrfPatterns: NO_CSRF_ENDPOINTS }))
  .use(pro.licensing())
  // for now no public access is allowed to worker (bar health check)
  .use((ctx, next) => {
    if (ctx.publicEndpoint) {
      return next()
    }
    if (
      (!ctx.isAuthenticated || (ctx.user && !ctx.user.budibaseAccess)) &&
      !ctx.internal
    ) {
      ctx.throw(403, "Unauthorized")
    }
    return next()
  })
  .use(middleware.auditLog)

router.get("/health", ctx => (ctx.status = 200))

// authenticated routes
for (let route of routes) {
  router.use(route.routes())
  router.use(route.allowedMethods())
}

export default router
