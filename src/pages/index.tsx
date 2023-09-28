import { Elysia } from "elysia";
import { BaseHtml } from "../components/base";
import { ctx } from "../context";

export const index = new Elysia()
  .use(ctx)
  .derive(async (ctx) => {
    const now = performance.now();
    const authRequest = ctx.auth.handleRequest(ctx);
    const session = await authRequest.validate();
    console.log("auth time", performance.now() - now);

    return { session };
  })
  .get("/", async ({ html, session }) => {
    return html(() => (
      <BaseHtml>
        <div class="flex flex-col items-center py-3">
          {session ? (
            <>
              <h1 class="text-2xl font-bold text-gray-800" safe>
                Hi! {session.user.name}
              </h1>
              <a
                href="/api/auth/signout"
                class="mt-4 rounded-lg bg-blue-500 px-4 py-2 text-white transition duration-200 hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-opacity-50"
              >
                Sign Out
              </a>
            </>
          ) : (
            <a
              href="/api/auth/login/google"
              hx-boost="false"
              class="mt-4 rounded-lg bg-blue-500 px-4 py-2 text-white transition duration-200 hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-opacity-50"
            >
              Sign In
            </a>
          )}
        </div>
      </BaseHtml>
    ));
  });
