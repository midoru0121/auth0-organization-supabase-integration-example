[英語](https://github.com/midoru0121/auth0-supabase-integration-example/blob/main/README.md)

# nextjs-auth0-supabase-integration-example

アプリケーションの基本的なフローです。
前提として、 `Supabase` と `Auth0` の署名アルゴリズムは `RS256` で統一するものとします。

- Auth0を使用してユーザーを認証します。
- Auth0でログイン直後に、事前にAuth0で作成したロールをユーザーに付与します。
- 上記のロールをペイロードに含め、SupabaseのJWTシークレットで署名し、それを@auth0/nextjs-auth0セッションに保存します。
  - 以降、このJWTはNext.jsのRSC内部でセッションとして取得可能です。このJWTはSupabaseへのアクセストークンとして使用されます。
- Next.jsのRSC内部からSupabaseにアクセスします（このとき、上記のアクセストークンをBearerトークンとしてリクエストに付与します）。
- Supabase側で、RLSポリシー用のJWTをデコードし、ロールが含まれているかを確認します。
  - ロールが含まれていない場合、テーブルへのアクセスを拒否します。
  - ロールが含まれている場合、テーブルへのアクセスを許可します。

## Auth0の設定

### Auth0アプリケーションの作成

Auth0に登録後、アプリケーションを作成して、 `Regular Web Applications` を選択して、作成します。

`Settings` をクリックして、設定に移動します。

![Image](https://github.com/user-attachments/assets/06465bbf-7b3a-4334-836e-c9bf1bc054cd)

`Domain`, `Client Id`, `Client Secret` を書き留めておきます。これらは後で使用します。

![Image](https://github.com/user-attachments/assets/644b5421-12aa-4583-853f-28940824ff17)

Allowed Callback URLsに `http://localhost:3000/api/auth/callback` を設定します。
Allowed Logout URLsに `http://localhost:3000` を設定します。

![Image](https://github.com/user-attachments/assets/05f17c99-4447-46a3-9816-57333af1aafb)

そして、OAuth and set JSON Web Token Signature を `RS256` に設定します。
そして、`OIDC Conformant` にチェックが入っていることをチェックします。

![Image](https://github.com/user-attachments/assets/59f1898e-18ef-47cc-a173-9b0ed2b6c803)

`Connection` に移動して、 `google-oauth-2` を設定して、Googleアカウントでサインアップできるようにします。

![googleOAuthConnection](https://github.com/user-attachments/assets/28683d31-91ee-4f2b-a41e-75044644a713)

### Auth0 Management APIの設定

Auth0 Management APIを選択し、`Machine to Machine Applications`を選択して、`Authrozedボタン` をチェックします。そして詳細を開きます。

![MachineToMachineApplications](https://github.com/user-attachments/assets/20cfbfd0-c189-444e-9cd8-fc492f2c7149)

![SelectAuth0ManagementAPI](https://github.com/user-attachments/assets/91b68db3-4d99-4cca-8628-40c67225a69d)

`read:users`, `update:users`, `read:roles` 権限をPermissionとして追加します。

![permissions](https://github.com/user-attachments/assets/0761dd70-b93b-401f-8bed-b08aabe6bfce)

### Roleを作成する

`Roles` をクリックして `Autenticated` ロールを作成します。これをデフォルトのロールとしてユーザーにアサインするようにします。

![IcreateRole1](https://github.com/user-attachments/assets/516318f3-3ff7-4528-9b0b-c0bf3f375cd3)

![IcreateRole2](https://github.com/user-attachments/assets/31872540-82d5-4527-b526-af33a1f21b00)

作成した `Authenticated` ロールの `Role ID` を書き留めておきます。後ほど使います。

![createRole3](https://github.com/user-attachments/assets/15639ae2-9c48-41ce-90b3-11e3fdcd74d6)

## Setting up Auth0 Post Login Action.

ユーザーのログイン時に、デフォルトロールを付与するために `Post Login Action` を設定します。

`Actions` の `Triggers` を選択、 `post-login` をクリックします。

![CreateAction](https://github.com/user-attachments/assets/6ad9758a-3601-4017-be23-1f6126e0e2a1)

メニューから `Build from scratch` を選択します。

![CreateAction2](https://github.com/user-attachments/assets/af677761-be0a-4d67-8104-6957e3fab4fc)

Actionを命名して `Create` をクリックします。

![CreateAction3](https://github.com/user-attachments/assets/7809b2d4-755f-4c4d-ac36-01a10d02726a)

`Secrets` を選択して、`DOMAIN`、`CLIENT_SECRET`、`CLIENT_ID`、 `DEFAULT_ROLE_ID` を追加します。

`DOMAIN`、`CLIENT_SECRET`、`CLIENT_ID`はアプリケーションの設定画面から参照できます。`DEFAULT_ROLE_ID` は先程作った、 `Authenticated` ロールのIDです。

![CreateAction5](https://github.com/user-attachments/assets/c4ff31d2-a28e-48ba-ae40-3548cbb39898)

`Add Dependency` をクリックして `auth0` と `axios` を追加します。

![createAction8](https://github.com/user-attachments/assets/cd519d3d-4e29-4f06-9456-accbc80fe118)

下記のコードを貼り付けます。

```javascript
exports.onExecutePostLogin = async (event, api) => {
  // Axiosをインポート

  const axios = require("axios").default;

  // Auth0 Management APIクライアントをインポート

  const { ManagementClient } = require("auth0");

  // カスタムクレーム用の名前空間を定義
  const roleNamespace = "https://auth0-supabase-interation-example.com/roles";

  // ユーザーが既にロールを持っている場合は処理を終了
  if (
    event.authorization &&
    event.authorization.roles &&
    event.authorization.roles.length > 0
  ) {
    console.log("The user has roles.");
    // 既存のロールをカスタムクレームとして設定
    const roles = event.authorization.roles.join(",");
    api.idToken.setCustomClaim(roleNamespace, roles);

    return;
  }

  try {
    // Management API用のアクセストークンを取得
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

    // Management APIクライアントを初期化
    const management = new ManagementClient({
      domain: event.secrets.DOMAIN,
      token: response.data.access_token,
    });

    // ユーザーにロールを割り当て
    const params = { id: event.user.user_id };
    const data = { roles: [event.secrets.DEFAULT_ROLE_ID] };

    await management.users.assignRoles(params, data);

    // APIからロールの詳細情報を取得
    const roleResponse = await axios.get(
      `https://${event.secrets.DOMAIN}/api/v2/roles/${event.secrets.DEFAULT_ROLE_ID}`,
      {
        headers: {
          Authorization: `Bearer ${response.data.access_token}`,
        },
      }
    );
    // ユーザーのロール名をIDトークンのカスタムクレームとして設定
    api.idToken.setCustomClaim(roleNamespace, roleResponse.data.name);

    console.log("Success");
  } catch (e) {
    // エラーをログに出力
    console.log(e);
  }
};
```

貼り付け終わったら、 `Deploy` をクリックします。

![CreateAction4](https://github.com/user-attachments/assets/e2082079-6b8c-48df-a2e1-4c458687fb9d)

先ほどの `post-login` の設定を開き、先ほど `Deploy` したアクションを `User Logged In` の直後にセットします。
これで、ユーザーがAuth0でログインしたときに、このアクションが走るようになり、すべてのユーザーに `Authenticated` ロールがアサインされるようになります。

![createAction7](https://github.com/user-attachments/assets/eb3e4872-4f25-4169-8902-8c2a16b8a79c)

### Organizationの作成

Organizationsをクリックして、 `Add Organization` を選択します。ここでは `example-organization` という organizationを作ります。

![Add Organization](https://github.com/user-attachments/assets/713e1f17-b073-467f-8555-1ea039317eef)

`Enable Connection` をクリックして、 `google-oauth2` を許可します。

![Enable Connection](https://github.com/user-attachments/assets/b5df03ed-7c0b-427a-8499-41ab1432fa45)

![Enable Google Oauth](https://github.com/user-attachments/assets/291898a5-52ba-4c75-8d69-718b0878f4ce)

`Applications` の `Organizations` の項目を開き `Business Users` を選択します。そして、 Login Flow で `prompt for Organization` を選択します。

![Application Organization](https://github.com/user-attachments/assets/57d87172-58a2-44bb-85e7-3a576f9546e6)

![Login Flow Prompt for Organization](https://github.com/user-attachments/assets/2a43831b-8ff7-491a-b771-8012e02d6176)

次に `Tenant Settings` の `Advanced` でTenant Login URIを設定します。 `https://` で始まるURLしか、許可されないので、 `https://127.0.0.1:3000/` を入力します。

![Set Tenant Login URI](https://github.com/user-attachments/assets/cd95ec9e-d34f-44d2-b318-37d79466f1e7)

次に、先ほど作った `Organization` にMemberを招待します。
自分が持っている `gmailのアドレス` に向けて招待メールを送ります。

![Invite Member](https://github.com/user-attachments/assets/9f12530d-3d56-4cf2-8489-26c20304edaa)

招待が完了したら、 `Members` を開き、上記の gmail アドレスを Memberとして追加しておきます。ここで `Add Members` しないとログインできません。

![Add Member](https://github.com/user-attachments/assets/45f1d0de-b2d2-4b00-8316-44cc24b166ea)

### 2: Creating a Supabase project

Supabaseに登録後、 Settings -> API に移動して、 `Project URL` , `anon key` と `JWT_SECRET` を書き留めておきます。

![APISetting](https://github.com/user-attachments/assets/601509da-8834-4156-8106-c145defa5710)

![jwtsecret](https://github.com/user-attachments/assets/887a3b56-2f70-4dce-be12-e53b1bb52556)

`todoテーブル` を作成します。

![createTable](https://github.com/user-attachments/assets/d3f8d608-2219-4882-8340-2542a28d1810)

`title` (text型) カラムを追加して、 `Save` をクリックします。

![createTable2](https://github.com/user-attachments/assets/ffdaa8a1-4982-4589-a6a8-49024cea5946)

また、 `organizationId` というカラムを `text型` で作っておきます。

![Todotable](https://github.com/user-attachments/assets/7f4f03e9-6c94-4ca4-bee0-d6bbffeb2f4e)

次に、 `todo` テーブルの `RLSポリシー` を作成します。

![SupabaseRunPoliciesSQL](https://github.com/user-attachments/assets/5b65d649-de0c-4880-94c7-81df8127f9cf)

こちらのSQLを Supabaseの `SQL Editor` にコピー&ペーストして `Run` します。

todoテーブルのRLSポリシーを設定します。 `Auth0` で設定した `Authenticated` ロールを持たないユーザー以外からの `INSERT` を禁止します。 `SELECT` , `UPDATE` , `DELETE` に関しては、organizationIdが一致していないユーザーからの操作を禁止します。

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

無事に作成されていれば、 `Policies` 画面で 下記の表示になります。

![SupabasePolicies](https://github.com/user-attachments/assets/fe9adae7-88ab-4388-8ed4-26e1f07074c7)

### 3 アプリの起動

`.env.local` ファイルを作成します。

```bash
# .env.local

# 下記のコマンドを叩いて作成されたシークレットを入力します。
# node -e "console.log(crypto.randomBytes(32).toString('hex'))"
# > この方法は https://github.com/auth0/nextjs-auth0 を参照しています。
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

起動して、 http://127.0.0.1:3000/ にアクセスします。 `https` で Next.js を起動します。

```bash
pnpm dev:https
```

![Login](https://github.com/user-attachments/assets/60e18305-431b-4a82-943e-6f799b306b87)

Auth0から `Invitation Mail` を送ったGmailの受信ボックスを確認します。Invitation Mailが届いていると思いますので、そのメールの内容のリンクをクリックします。

![AcceptInvitation](https://github.com/user-attachments/assets/94995639-df4f-44af-a46f-1f163001aa9f)

リンクをクリックした先で、`example-organization` と入力して、ログインします。

![Login](https://github.com/user-attachments/assets/8b6a0cd6-4a23-48dd-807d-6413d39ecb86)

ログインが完了したら、

https://127.0.0.1:3000/protected にアクセスします。このページにはAuth0でログインしていないとアクセスできないようになっています。

このページで、SupabaseのtodoテーブルにInsertしたデータが表示されれば、成功です。

![AddItem](https://github.com/user-attachments/assets/cfb9c9f6-d366-4120-a4b3-ea61dba57d5a)

![ItemAdded](https://github.com/user-attachments/assets/5c81b27e-a9e1-405b-acfd-9f56a649223a)
