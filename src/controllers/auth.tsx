import { OAuthRequestError } from "@lucia-auth/oauth";
import { Elysia } from "elysia";
import { parseCookie } from "elysia/cookie";
import { serializeCookie } from "lucia/utils";
import { googleAuth } from "../auth/index";
import { config } from "../config";
import { ctx } from "../context";
import { redirect } from "../lib";

export const authController = new Elysia({
  prefix: "/auth",
})
  .use(ctx)
  .post("/signout", async (ctx) => {
    const authRequest = ctx.auth.handleRequest(ctx);
    const session = await authRequest.validate();

    if (!session) {
      redirect(
        {
          set: ctx.set,
          headers: ctx.headers,
        },
        "/",
      );
      return;
    }

    await ctx.auth.invalidateSession(session.sessionId);

    const sessionCookie = ctx.auth.createSessionCookie(null);

    ctx.set.headers["Set-Cookie"] = sessionCookie.serialize();
    redirect(
      {
        set: ctx.set,
        headers: ctx.headers,
      },
      "/",
    );
  })
  .get("/login/google", async ({ set }) => {
    const [url, state] = await googleAuth.getAuthorizationUrl();

    const state_cookie = serializeCookie("google_auth_state", state, {
      maxAge: 60 * 60,
      httpOnly: true,
      secure: config.env.NODE_ENV === "production",
      path: "/",
    });

    set.headers["Set-Cookie"] = state_cookie;

    set.redirect = url.toString();
  })
  .get("/google/callback", async ({ set, query, headers, auth, log }) => {
    const { state, code } = query;

    const cookies = parseCookie(headers["cookie"] || ""); // also typing issues here. Eslint also prefered dot-notation
    const state_cookie = cookies["google_auth_state"]; // dot-notation preferred by eslint

    if (!state_cookie || !state || state_cookie !== state || !code) {
      // typing issues here? Do I need to do a state_cookie.value?
      set.status = "Unauthorized";
      console.log("Unauthorized - about to return");
      return;
    }

    try {
      const { createUser, getExistingUser, googleUser } =
        await googleAuth.validateCallback(code);

      const getUser = async () => {
        const existingUser = await getExistingUser();

        if (existingUser) {
          return existingUser;
        }

        const user = await createUser({
          attributes: {
            name: googleUser.name,
            email: googleUser.email ?? null,
            picture: googleUser.picture,
          },
        });

        return user;
      };

      const user = await getUser();

      const session = await auth.createSession({
        userId: user.userId,
        attributes: {},
      });

      const sessionCookie = auth.createSessionCookie(session);

      //await syncIfLocal();

      set.headers["Set-Cookie"] = sessionCookie.serialize();

      redirect(
        {
          set,
          headers,
        },
        "/", // /new-user
      );
    } catch (error) {
      log.error(error, "Error signing in with Google");

      if (error instanceof OAuthRequestError) {
        set.status = "Unauthorized";
        return;
      } else {
        set.status = "Internal Server Error";
        return;
      }
    }
  });
