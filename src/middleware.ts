// Protect routes that require authentication using Auth0 middleware
import {
  getSession,
  withMiddlewareAuthRequired,
} from "@auth0/nextjs-auth0/edge";

const AUTH0_LOGOUT_URL = "/api/auth/logout";

import { NextResponse } from "next/server";

export default withMiddlewareAuthRequired(async function middleware(req) {
  try {
    // Create response object
    const res = NextResponse.next();
    // Get session information
    const session = await getSession(req, res);

    // If session doesn't exist, redirect to logout URL
    if (!session) {
      return NextResponse.redirect(new URL(AUTH0_LOGOUT_URL, req.url));
    }

    // Check Supabase token expiration (current time + 1 hour > token expiration)
    const isSupabaseTokenExpired =
      Math.floor(Date.now() / 1000) > session.supabaseAccessTokenExpiredAt;

    // If Supabase token is expired, redirect to logout URL
    if (isSupabaseTokenExpired) {
      return NextResponse.redirect(new URL(AUTH0_LOGOUT_URL, req.url));
    }

    // Return original response if no issues
    return res;
  } catch (error) {
    // Redirect to error page if an error occurs
    console.error("Middleware error:", error);
    throw error;
  }
});

// Apply middleware to all paths starting with protected
export const config = {
  matcher: "/protected/:path*",
};
