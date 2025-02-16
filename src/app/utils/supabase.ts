import { createClient, SupabaseClientOptions } from '@supabase/supabase-js'

const getSupabase = (access_token: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const options: SupabaseClientOptions<any> = {}

  if (access_token) {
    options.global = {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    }
  }

  if(!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ) {
    throw new Error("NEXT_PUBLIC_SUPABASE_URL || NEXT_PUBLIC_SUPABASE_ANON_KEY not set")
  }

  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    options
  )

  return supabase
}

export { getSupabase }