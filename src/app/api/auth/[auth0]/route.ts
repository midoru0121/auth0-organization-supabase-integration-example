import {
  AfterCallbackAppRoute,
  handleAuth,
  handleCallback,
  handleLogin,
  handleLogout,
  Session,
} from "@auth0/nextjs-auth0";
import { NextApiRequest, NextApiResponse } from "next";
import jwt from "jsonwebtoken";
import { NextRequest } from "next/server";

// Function executed after Auth0 callback
const afterCallback: AfterCallbackAppRoute = async (
  req: NextRequest,
  session: Session
) => {
  // Get user roles assigned in Auth0 (comma-separated)
  const userRoles =
    session?.user["https://auth0-supabase-interation-example.com/roles"];

  // Create JWT token payload for Supabase authentication
  // userRoles: Convert comma-separated roles from Auth0 to array
  // userId: Auth0 user ID
  // organizationId: Auth0 organization ID
  // exp: Token expiration (1 hour from current time)
  const supabaseJWTPayload = {
    userRoles: userRoles.split(","),
    userId: session.user.sub,
    organizationId: session.user.org_id,
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
  };

  // Check environment variable
  if (!process.env.SUPABASE_JWT_SECRET) {
    throw new Error("SUPABASE_JWT_SECRET not set");
  }

  session.supabaseAccessTokenExpiredAt = supabaseJWTPayload.exp;

  // Generate JWT token and add to session for Supabase authentication
  session.user.supabaseAccessToken = jwt.sign(
    supabaseJWTPayload,
    process.env.SUPABASE_JWT_SECRET
  );
  // Generate JWT token using user roles and ID from Auth0
  // Token expires in 1 hour
  // Generated token is used for Supabase authentication
  return session;
};

// Auth0 authentication handler
export const GET = handleAuth({
  async login(req: NextRequest) {
    return handleLogin(req, {
      authorizationParams: {
        invitation: req.nextUrl.searchParams.get("invitation"),
        organization: req.nextUrl.searchParams.get("organization"),
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
  },
  // Callback processing
  async callback(req: NextApiRequest, res: NextApiResponse) {
    try {
      const response = await handleCallback(req, res, {
        afterCallback,
      });
      return response;
    } catch (error) {
      // Error handling
      if (error instanceof Error) {
        return new Response(error.message, { status: 500 });
      }
      return new Response("An unknown error occurred.", { status: 500 });
    }
  },
  // Logout processing
  logout: handleLogout({
    returnTo: "/",
  }),
});
