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
