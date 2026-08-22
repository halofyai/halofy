/** HaloMem HTTP transport — public surface (M1 module B). */

export {
  createHttpServer,
  type HaloHttpServer,
  type HttpServerDeps,
  type HttpAuth,
  type HttpSyscalls,
  type HttpAdmin,
  type HttpMetrics,
  type HttpAudit,
} from "./server.js";
