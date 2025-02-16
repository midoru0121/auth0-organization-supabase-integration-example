import { getSession } from "@auth0/nextjs-auth0";
import { getSupabase } from "../utils/supabase";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";

// Server Action: Add TODO
async function addTodo(formData: FormData) {
  "use server";

  const session = await getSession();
  if (!session?.user?.supabaseAccessToken) {
    throw new Error("Authentication Error");
  }

  const title = formData.get("title");
  if (!title) {
    throw new Error("Title is required");
  }

  const supabase = getSupabase(session.user.supabaseAccessToken);
  const { error } = await supabase
    .from("todo")
    .insert([{ title, organizationId: session.user.org_id }]);

  if (error) {
    if ("JWT expired" === error.message) {
      redirect("/api/auth/logout");
    }
    throw new Error(error.message);
  }

  revalidatePath("/protected");
}

export default async function ProtectedPage() {
  // Get user session
  const session = await getSession();

  // Redirect to home if session or user doesn't exist
  if (!session || !session.user) {
    redirect("/");
  }

  // Check Supabase access token
  if (!session.user.supabaseAccessToken) {
    throw new Error("No supabaseAccessToken");
  }

  // Initialize Supabase client
  const supabase = getSupabase(session.user.supabaseAccessToken);
  // Get all todos from database
  const { data, error } = await supabase.from("todo").select("*");

  // Error handling
  if (error) {
    // Log error
    console.log(error);

    // If Supabase JWT is expired, logout from Auth0
    if ("JWT expired" === error.message) {
      redirect("/api/auth/logout");
    }

    // Throw other errors
    throw new Error(error?.message);
  }

  // Return message if no data exists
  if (!data) {
    return "No data";
  }

  // Render todo list and form
  return (
    <div>
      <form action={addTodo}>
        <input type="text" name="title" placeholder="Enter TODO" required />
        <button type="submit">Add</button>
      </form>

      <ul>
        {data.map((todo) => (
          <li key={todo.id}>{todo.title}</li>
        ))}
      </ul>
    </div>
  );
}
