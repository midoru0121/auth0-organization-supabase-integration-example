[日本語](https://github.com/midoru0121/auth0-supabase-integration-example/blob/main/README_ja.md)

# nextjs-auth0-supabase-integration-example

This is the flow of the application. Assumption: The signing algorithm for both Supabase and Auth0 is set to `RS256`.

- Authenticate the user using Auth0.
- Immediately after logging in via Auth0, assign the role previously created in Auth0 to the user.
- Include the above role in the payload, sign it with Supabase’s JWT secret, and store it in the @auth0/nextjs-auth0 session.
  - From here on, it can be accessed as a session inside Next.js’s RSC. This JWT will be used as an access token for Supabase.
- Access Supabase from within Next.js’s RSC (when doing this, attach the above access token as a Bearer token in the request).
- On the Supabase side, decode the JWT for the RLS policy and check if the role is included.
  - If the role is not included, deny access to the table.
  - If the role is included, grant access to the table.

## Setting Up Auth0

### Creating an Auth0 Application

After registering with Auth0, create an application and select `Regular Web Applications`.

Click `Settings` to navigate to the configuration page.

![Image](https://github.com/user-attachments/assets/06465bbf-7b3a-4334-836e-c9bf1bc054cd)

Note down `Domain`, `Client Id`, and `Client Secret`, as they will be needed later.

![Image](https://github.com/user-attachments/assets/05f17c99-4447-46a3-9816-57333af1aafb)

Set `Allowed Callback URLs` to `http://localhost:3000/api/auth/callback`.
Set `Allowed Logout URLs` to `http://localhost:3000`.

![Image](https://github.com/user-attachments/assets/644b5421-12aa-4583-853f-28940824ff17)

Then, set `OAuth` and `JSON Web Token Signature` to `RS256`. Also, check that the `OIDC Conformant` box is checked.

![Image](https://github.com/user-attachments/assets/59f1898e-18ef-47cc-a173-9b0ed2b6c803)

Go to `Connections` and enable `google-oauth-2` to allow sign-ups via Google accounts.

![googleOAuthConnection](https://github.com/user-attachments/assets/28683d31-91ee-4f2b-a41e-75044644a713)

### Configuring the Auth0 Management API

Select the Auth0 Management API, choose `Machine to Machine Applications`, and check the `Authorized` button. Then, expand the details.

![MachineToMachineApplications](https://github.com/user-attachments/assets/20cfbfd0-c189-444e-9cd8-fc492f2c7149)

![SelectAuth0ManagementAPI](https://github.com/user-attachments/assets/91b68db3-4d99-4cca-8628-40c67225a69d)

Add the following permissions: `read:users`, `update:users`, and `read:roles`.

![permissions](https://github.com/user-attachments/assets/0761dd70-b93b-401f-8bed-b08aabe6bfce)

### Creating a Role

Click `Roles` and create an `Authenticated` role. This role will be assigned to users by default.

![IcreateRole1](https://github.com/user-attachments/assets/516318f3-3ff7-4528-9b0b-c0bf3f375cd3)

![IcreateRole2](https://github.com/user-attachments/assets/31872540-82d5-4527-b526-af33a1f21b00)

Note the `Role ID` of the `Authenticated` role, as it will be used later.

![createRole3](https://github.com/user-attachments/assets/15639ae2-9c48-41ce-90b3-11e3fdcd74d6)

## Setting Up Auth0 Post Login Action

To assign a default role upon user login, set up a `Post Login Action`.

Go to `Actions` > `Triggers` and click `post-login`.

![CreateAction](https://github.com/user-attachments/assets/6ad9758a-3601-4017-be23-1f6126e0e2a1)

Select `Build from scratch`.

![CreateAction2](https://github.com/user-attachments/assets/af677761-be0a-4d67-8104-6957e3fab4fc)

Name the action and click `Create`.

![CreateAction3](https://github.com/user-attachments/assets/7809b2d4-755f-4c4d-ac36-01a10d02726a)

Go to `Secrets` and add `DOMAIN`, `CLIENT_SECRET`, `CLIENT_ID`, and `DEFAULT_ROLE_ID`.

![CreateAction5](https://github.com/user-attachments/assets/c4ff31d2-a28e-48ba-ae40-3548cbb39898)

Click `Add Dependency` and add `auth0` and `axios`.

![createAction8](https://github.com/user-attachments/assets/cd519d3d-4e29-4f06-9456-accbc80fe118)

Paste the following code:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  // Import Axios

  const axios = require("axios").default;

  // Import Auth0 Management API client

  const { ManagementClient } = require("auth0");

  // Define a namespace for custom claims
  const roleNamespace = "https://auth0-supabase-interation-example.com/roles";

  // If the user already has roles, exit the process
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
    // Get the access token for the Management API
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

    // Initialize the Management API client
    const management = new ManagementClient({
      domain: event.secrets.DOMAIN,
      token: response.data.access_token,
    });

    // Assign roles to the user
    const params = { id: event.user.user_id };
    const data = { roles: [event.secrets.DEFAULT_ROLE_ID] };

    await management.users.assignRoles(params, data);

    // Get role details from the API
    const roleResponse = await axios.get(
      `https://${event.secrets.DOMAIN}/api/v2/roles/${event.secrets.DEFAULT_ROLE_ID}`,
      {
        headers: {
          Authorization: `Bearer ${response.data.access_token}`,
        },
      }
    );
    // Set the role name of the user as a custom claim in the ID token
    api.idToken.setCustomClaim(roleNamespace, roleResponse.data.name);

    console.log("Success");
  } catch (e) {
    // Log the error
    console.log(e);
  }
};
```

Click `Deploy`.

![CreateAction4](https://github.com/user-attachments/assets/e2082079-6b8c-48df-a2e1-4c458687fb9d)

Return to the `post-login` configuration and place the deployed action right after `User Logged In`.

![createAction7](https://github.com/user-attachments/assets/eb3e4872-4f25-4169-8902-8c2a16b8a79c)

## Creating a Supabase Project

After registering with Supabase, go to `Settings -> API` and note the `Project URL`, `anon key`, and `JWT_SECRET`.

![APISetting](https://github.com/user-attachments/assets/601509da-8834-4156-8106-c145defa5710)

![jwtsecret](https://github.com/user-attachments/assets/887a3b56-2f70-4dce-be12-e53b1bb52556)

Create a `todo` table.

![createTable](https://github.com/user-attachments/assets/d3f8d608-2219-4882-8340-2542a28d1810)

Add a `title` (text type) column and click `Save`.

![createTable2](https://github.com/user-attachments/assets/ffdaa8a1-4982-4589-a6a8-49024cea5946)

Insert some sample data.

![createTable3](https://github.com/user-attachments/assets/2fada978-8f2b-437b-b6c2-1948b2c3ee05)

Set an RLS policy on the `todo` table to restrict access to users without the `Authenticated` role.

```sql
alter policy "JWT Authenticated can view todo"
on "public"."todo"
to public
using (
  ((auth.jwt() -> 'userRoles'::text) ? 'Authenticated'::text)
);
```

![jwt](https://github.com/user-attachments/assets/a8ada4bb-a8e5-42f9-b056-8c16e341c645)

Click `Save Policy`.

## Running the Application

Create a `.env.local` file:

```bash
# .env.local
AUTH0_SECRET=any-secure-value
AUTH0_BASE_URL=http://localhost:3000
AUTH0_ISSUER_BASE_URL=https://<your-tenant>.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
NEXT_PUBLIC_SUPABASE_URL=your-supabase-url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret
```

Start the application and visit http://localhost:3000.

```bash
pnpm dev
```

![Login](https://github.com/user-attachments/assets/60e18305-431b-4a82-943e-6f799b306b87)

Click `Login` and authenticate via email or Google OAuth. Then, visit http://localhost:3000/protected to verify data retrieval.

![afterLogin](https://github.com/user-attachments/assets/0560986f-e037-42b9-8c84-3aaec014843a)
