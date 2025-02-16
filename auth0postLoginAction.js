/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  // Import Axios
  const axios = require("axios").default;

  // Import Auth0 Management API client
  const { ManagementClient } = require("auth0");

  // Define namespace for custom claims
  const roleNamespace = "https://auth0-supabase-interation-example.com/roles";

  // Exit if user already has roles
  if (
    event.authorization &&
    event.authorization.roles &&
    event.authorization.roles.length > 0
  ) {
    console.log("This user have roles.");
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
