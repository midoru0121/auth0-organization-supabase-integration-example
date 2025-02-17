[日本語](https://github.com/midoru0121/auth0-supabase-integration-example/blob/main/README_ja.md)

# nextjs-auth0-supabase-integration-example

Here is the basic flow of the application.
As a prerequisite, the signing algorithms for both `Supabase` and `Auth0` should be unified as `RS256`.

- Authenticate users using Auth0
- After logging in with Auth0, assign roles to users that were previously created in Auth0
- Include these roles in the payload, sign it with Supabase's JWT secret, and store it in the @auth0/nextjs-auth0 session
  - This JWT can then be retrieved as a session within Next.js RSC. This JWT is used as an access token for Supabase.
- Access Supabase from within Next.js RSC (attaching the above access token as a Bearer token in the request)
- On the Supabase side, decode the JWT for RLS policies and verify if roles are included
  - If roles are not included, deny access to tables
  - If roles are included, allow access to tables

## Auth0 Setup

### Creating an Auth0 Application

After registering with Auth0, create an application by selecting `Regular Web Applications`.

Click on `Settings` to move to the configuration page.

![Image](https://github.com/user-attachments/assets/06465bbf-7b3a-4334-836e-c9bf1bc054cd)

Note down the `Domain`, `Client Id`, and `Client Secret`. These will be used later.

![Image](https://github.com/user-attachments/assets/644b5421-12aa-4583-853f-28940824ff17)

Set `http://localhost:3000/api/auth/callback` in Allowed Callback URLs.
Set `http://localhost:3000` in Allowed Logout URLs.

![Image](https://github.com/user-attachments/assets/05f17c99-4447-46a3-9816-57333af1aafb)

Set the OAuth and JSON Web Token Signature to `RS256`.
Ensure that `OIDC Conformant` is checked.

![Image](https://github.com/user-attachments/assets/59f1898e-18ef-47cc-a173-9b0ed2b6c803)

Go to `Connection` and set up `google-oauth-2` to enable sign-up with Google accounts.

![googleOAuthConnection](https://github.com/user-attachments/assets/28683d31-91ee-4f2b-a41e-75044644a713)

### Setting up Auth0 Management API

Select Auth0 Management API, choose `Machine to Machine Applications`, and check the `Authorized button`. Then open the details.

![MachineToMachineApplications](https://github.com/user-attachments/assets/20cfbfd0-c189-444e-9cd8-fc492f2c7149)

![SelectAuth0ManagementAPI](https://github.com/user-attachments/assets/91b68db3-4d99-4cca-8628-40c67225a69d)

Add `read:users`, `update:users`, `read:roles` as Permissions.

![permissions](https://github.com/user-attachments/assets/0761dd70-b93b-401f-8bed-b08aabe6bfce)

### Creating Roles

Click on `Roles` and create an `Authenticated` role. This will be assigned to users as the default role.

![IcreateRole1](https://github.com/user-attachments/assets/516318f3-3ff7-4528-9b0b-c0bf3f375cd3)

![IcreateRole2](https://github.com/user-attachments/assets/31872540-82d5-4527-b526-af33a1f21b00)

Note down the `Role ID` of the created `Authenticated` role. We'll use it later.

![createRole3](https://github.com/user-attachments/assets/15639ae2-9c48-41ce-90b3-11e3fdcd74d6)

## Setting up Auth0 Post Login Action

To assign default roles to users upon login, we'll set up a `Post Login Action`.

Select `Triggers` under `Actions`, then click on `post-login`.

![CreateAction](https://github.com/user-attachments/assets/6ad9758a-3601-4017-be23-1f6126e0e2a1)

Select `Build from scratch` from the menu.

![CreateAction2](https://github.com/user-attachments/assets/af677761-be0a-4d67-8104-6957e3fab4fc)

Name the Action and click `Create`.

![CreateAction3](https://github.com/user-attachments/assets/7809b2d4-755f-4c4d-ac36-01a10d02726a)

Select `Secrets` and add `DOMAIN`, `CLIENT_SECRET`, `CLIENT_ID`, and `DEFAULT_ROLE_ID`.

You can find `DOMAIN`, `CLIENT_SECRET`, and `CLIENT_ID` in the application settings screen. `DEFAULT_ROLE_ID` is the ID of the `Authenticated` role we created earlier.

![CreateAction5](https://github.com/user-attachments/assets/c4ff31d2-a28e-48ba-ae40-3548cbb39898)

Click `Add Dependency` and add `auth0` and `axios`.

![createAction8](https://github.com/user-attachments/assets/cd519d3d-4e29-4f06-9456-accbc80fe118)

下記のコードを貼り付けます。

```javascript
exports.onExecutePostLogin = async (event, api) => {
  // Import Axios
  const axios = require("axios").default;

  // Import Auth0 Management API client
  const { ManagementClient } = require("auth0");

  // Define namespace for custom claims
  const roleNamespace = "https://auth0-supabase-interation-example.com/roles";

  // If user already has roles, end processing
  if (
    event.authorization &&
    event.authorization.roles &&
    event.authorization.roles.length > 0
  ) {
    console.log("The user has roles.");
    // Set existing roles as custom claims
    const roles = event.authorization.roles.join(",");
    api.idToken.setCustomClaim(roleNamespace, roles);

    return;
  }

  try {
    // Get access token for Management API
    const options = {
      method: "POST",
      url: `https://${event.secrets.DOMAIN}/oauth/token`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: event.secrets.CLIENT_ID,
        client_secret: event.secrets.CLIENT_SECRET,
        audience: `https://${event.secrets.DOMAIN}/api/v2/`,
        scope: "read:roles update:users",
      }),
    };

    const response = await axios.request(options);

    // Initialize Management API client
    const management = new ManagementClient({
      domain: event.secrets.DOMAIN,
      token: response.data.access_token,
    });

    // Assign roles to user
    const params = { id: event.user.user_id };
    const data = { roles: [event.secrets.DEFAULT_ROLE_ID] };

    await management.users.assignRoles(params, data);

    // Get role details from API
    const roleResponse = await axios.get(
      `https://${event.secrets.DOMAIN}/api/v2/roles/${event.secrets.DEFAULT_ROLE_ID}`,
      {
        headers: {
          Authorization: `Bearer ${response.data.access_token}`,
        },
      }
    );
    // Set user's role name as custom claim in ID token
    api.idToken.setCustomClaim(roleNamespace, roleResponse.data.name);

    console.log("Success");
  } catch (e) {
    // Log error
    console.log(e);
  }
};
```

After pasting, click `Deploy`.

![CreateAction4](https://github.com/user-attachments/assets/e2082079-6b8c-48df-a2e1-4c458687fb9d)

Open the `post-login` settings and set the action you just deployed immediately after `User Logged In`.
This will make the action run when users log in to Auth0, assigning the `Authenticated` role to all users.

![createAction7](https://github.com/user-attachments/assets/eb3e4872-4f25-4169-8902-8c2a16b8a79c)

### Organizationの作成

Click on Organizations and select `Add Organization`. Here, we will create an organization called `example-organization`.

![Add Organization](https://github.com/user-attachments/assets/713e1f17-b073-467f-8555-1ea039317eef)

Click on `Enable Connection` and enable `google-oauth2`.

![Enable Connection](https://github.com/user-attachments/assets/b5df03ed-7c0b-427a-8499-41ab1432fa45)

![Enable Google Oauth](https://github.com/user-attachments/assets/291898a5-52ba-4c75-8d69-718b0878f4ce)

Open the `Organizations` section in `Applications`, select `Business Users`. Then, select `prompt for Organization` in the Login Flow.

![Application Organization](https://github.com/user-attachments/assets/57d87172-58a2-44bb-85e7-3a576f9546e6)

![Login Flow Prompt for Organization](https://github.com/user-attachments/assets/2a43831b-8ff7-491a-b771-8012e02d6176)

Next, set the Tenant Login URI in `Advanced` under `Tenant Settings`. Since only URLs starting with `https://` are allowed, enter `https://127.0.0.1:3000/`.

![Set Tenant Login URI](https://github.com/user-attachments/assets/cd95ec9e-d34f-44d2-b318-37d79466f1e7)

Next, let's invite a Member to the `Organization` we just created.
Send an invitation email to your `Gmail address`.

![Invite Member](https://github.com/user-attachments/assets/9f12530d-3d56-4cf2-8489-26c20304edaa)

After the invitation is complete, open `Members` and add the Gmail address above as a Member. You won't be able to log in unless you `Add Members` here.

![Add Member](https://github.com/user-attachments/assets/45f1d0de-b2d2-4b00-8316-44cc24b166ea)

### 2: Creating a Supabase project

After registering with Supabase, go to Settings -> API and note down the `Project URL`, `anon key` and `JWT_SECRET`.

![APISetting](https://github.com/user-attachments/assets/601509da-8834-4156-8106-c145defa5710)

![jwtsecret](https://github.com/user-attachments/assets/887a3b56-2f70-4dce-be12-e53b1bb52556)

Create a `todo table`.

![createTable](https://github.com/user-attachments/assets/d3f8d608-2219-4882-8340-2542a28d1810)

Add a `title` column (type: text) and click `Save`.

![createTable2](https://github.com/user-attachments/assets/ffdaa8a1-4982-4589-a6a8-49024cea5946)

Also, create a column called `organizationId` with type `text`.

![Todotable](https://github.com/user-attachments/assets/7f4f03e9-6c94-4ca4-bee0-d6bbffeb2f4e)

Next, create `RLS policies` for the `todo` table.

![SupabaseRunPoliciesSQL](https://github.com/user-attachments/assets/5b65d649-de0c-4880-94c7-81df8127f9cf)

Copy and paste this SQL into Supabase's `SQL Editor` and click `Run`.

Set up RLS policies for the todo table. This prohibits `INSERT` operations from users who don't have the `Authenticated` role set in `Auth0`. For `SELECT`, `UPDATE`, and `DELETE` operations, it prohibits actions from users whose organizationId doesn't match.

```sql
DROP POLICY IF EXISTS "JWT Authenticated can insert todo" ON public.todo;

-- This policy allows users with 'Authenticated' role to insert todos
-- The user must have an organizationId in their JWT token
CREATE POLICY "JWT Authenticated can insert todo"
ON public.todo
FOR INSERT
WITH CHECK (
  ((auth.jwt() -> 'userRoles'::text) ? 'Authenticated'::text)
  AND
  ((auth.jwt() ->> 'organizationId')::text IS NOT NULL)
);

DROP POLICY IF EXISTS "JWT Authenticated can select todo" ON public.todo;

-- This policy allows users with 'Authenticated' role to select todos
-- The user can only select todos that belong to their organization
CREATE POLICY "JWT Authenticated can select todo"
ON public.todo
FOR SELECT
USING (
  ((auth.jwt() -> 'userRoles'::text) ? 'Authenticated'::text)
  AND
  ((auth.jwt() ->> 'organizationId')::text = "organizationId"::text)
);

DROP POLICY IF EXISTS "JWT Authenticated can update todo" ON public.todo;

-- This policy allows users with 'Authenticated' role to update todos
-- The user can only update todos that belong to their organization
CREATE POLICY "JWT Authenticated can update todo"
ON public.todo
FOR UPDATE
USING (
  ((auth.jwt() -> 'userRoles'::text) ? 'Authenticated'::text)
  AND
  ((auth.jwt() ->> 'organizationId')::text = "organizationId"::text)
);

DROP POLICY IF EXISTS "JWT Authenticated can delete todo" ON public.todo;
-- This policy allows users with 'Authenticated' role to delete todos
-- The user can only delete todos that belong to their organization
CREATE POLICY "JWT Authenticated can delete todo"
ON public.todo
FOR DELETE
USING (
  ((auth.jwt() -> 'userRoles'::text) ? 'Authenticated'::text)
  AND
  ((auth.jwt() ->> 'organizationId')::text = "organizationId"::text)
);

```

If created successfully, the `Policies` screen should look like the following.

![SupabasePolicies](https://github.com/user-attachments/assets/fe9adae7-88ab-4388-8ed4-26e1f07074c7)

### 3 Launching the Application

Create `.env.local` .

```bash
# .env.local

# Enter the secret generated by running the command below
# node -e "console.log(crypto.randomBytes(32).toString('hex'))"
# >  https://github.com/auth0/nextjs-auth0
AUTH0_SECRET=any-secure-value
AUTH0_BASE_URL=http://localhost:3000

# You can find Auth0 values in the Settings section under Basic Information for your application.
# The url of your Auth0 tenant domain
AUTH0_ISSUER_BASE_URL=https://<name-of-your-tenant>.<region-you-selected>.auth0.com
AUTH0_CLIENT_ID=get-from-auth0-dashboard
AUTH0_CLIENT_SECRET=get-from-auth0-dashboard

# You can find the Supabase values under Settings > API for your project.
NEXT_PUBLIC_SUPABASE_URL=get-from-supabase-dashboard
NEXT_PUBLIC_SUPABASE_ANON_KEY=get-from-supabase-dashboard
SUPABASE_JWT_SECRET=get-from-supabase-dashboard
```

Launch and access http://127.0.0.1:3000/. Start Next.js with `https`.

```bash
pnpm dev:https
```

![Login](https://github.com/user-attachments/assets/60e18305-431b-4a82-943e-6f799b306b87)

Check your Gmail inbox for the Invitation Mail sent from Auth0. You should have received the invitation email - click the link in the email.

![AcceptInvitation](https://github.com/user-attachments/assets/94995639-df4f-44af-a46f-1f163001aa9f)

On the page that opens after clicking the link, enter `example-organization` and log in.

![Login](https://github.com/user-attachments/assets/8b6a0cd6-4a23-48dd-807d-6413d39ecb86)

After logging in successfully,

Access https://127.0.0.1:3000/protected. This page is only accessible when logged in with Auth0.

If you can see the data you inserted into the Supabase todo table on this page, the setup was successful.

![AddItem](https://github.com/user-attachments/assets/cfb9c9f6-d366-4120-a4b3-ea61dba57d5a)

![ItemAdded](https://github.com/user-attachments/assets/5c81b27e-a9e1-405b-acfd-9f56a649223a)
