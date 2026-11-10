import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.3";
import { hkNow } from "https://cdn.jsdelivr.net/gh/willthree123/tmp-manage-users-redeploy-mwa0zsnu@main/hkDatetime.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS, DELETE, PUT",
};

/**
 * Platform-level roles live in `public.platform_staff` (admin | maintainer).
 * A buyer is the *absence* of a row there — there is no "customer" role to hold
 * any more (D1/D12). `AccountType` is the wire shape the admin UI speaks.
 */
type PlatformRole = "admin" | "maintainer";
type AccountType = PlatformRole | "non_staff";

/**
 * The service-role client. Typed via `ReturnType` rather than the file's usual bare
 * `any`, so these helpers cannot silently accept the wrong client.
 */
type SupabaseAdminClient = ReturnType<typeof createClient>;

/**
 * Retired literals are tolerated so a stale client build does not hard-fail, but
 * they are never persisted:
 *   customer          -> non_staff (the same person, renamed)
 *   organization_user -> rejected: organization standing is a membership, not a
 *                        platform role, and must not be granted by writing a role.
 */
function normalizeAccountType(value: unknown): AccountType {
  if (value === "admin" || value === "maintainer") return value;
  if (value === "non_staff" || value === "customer") return "non_staff";
  if (value === "organization_user") {
    throw new Error(
      "organization_user is no longer a platform role. Organization access comes from organization_members: use the admin assign path (organizationId + memberRole) or the owner invitation flow.",
    );
  }
  throw new Error(`Unsupported account type: ${String(value)}`);
}

function isPlatformRole(value: unknown): value is PlatformRole {
  return value === "admin" || value === "maintainer";
}

/** Reads the caller's/target's platform role. Absence of a row means a buyer. */
async function loadPlatformRole(supabaseAdmin: SupabaseAdminClient, userId: string): Promise<PlatformRole | null> {
  const { data, error } = await supabaseAdmin
    .from("platform_staff")
    .select("role")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw error;
  return isPlatformRole(data?.role) ? data.role : null;
}

/**
 * The single grant/revoke primitive. `non_staff` means "no row", which is why this
 * is a DELETE rather than a write of a sentinel value.
 */
async function setPlatformRole(supabaseAdmin: SupabaseAdminClient, userId: string, accountType: AccountType, actorId: string): Promise<void> {
  if (accountType === "non_staff") {
    const { error } = await supabaseAdmin.from("platform_staff").delete().eq("user_id", userId);
    if (error) throw error;
    return;
  }

  const { error } = await supabaseAdmin
    .from("platform_staff")
    .upsert(
      { user_id: userId, role: accountType, granted_by: actorId, updated_by: actorId },
      { onConflict: "user_id" },
    );
  if (error) throw error;
}

/**
 * Active admins = platform_staff admins whose account is not deactivated. Deactivation
 * is checked because an inactive admin cannot sign in, so they cannot let you back in.
 *
 * Two queries rather than an embedded `users(...)`: `platform_staff` has three foreign
 * keys into `users` (user_id, granted_by, updated_by), so PostgREST cannot infer which
 * one to embed and returns an ambiguity error instead.
 */
async function countActiveAdmins(supabaseAdmin: SupabaseAdminClient): Promise<number> {
  const { data: adminRows, error } = await supabaseAdmin.from("platform_staff").select("user_id").eq("role", "admin");
  if (error) throw error;

  const adminIds: string[] = (adminRows ?? []).map((row) => String(row.user_id)).filter(Boolean);
  if (adminIds.length === 0) return 0;

  const { data: activeRows, error: activeError } = await supabaseAdmin.from("users").select("id").in("id", adminIds).eq("is_active", true);
  if (activeError) throw activeError;
  return (activeRows ?? []).length;
}

/** Keep in sync with src/config/appConfig.ts PASSWORD_POLICY (Deno cannot import app modules). */
const PASSWORD_POLICY = {
  MIN_LENGTH: 8,
  MAX_LENGTH: 128,
  SPECIAL_CHAR_PATTERN: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/,
};

const EXPORT_USERS_MAX = 5000;
const EXPORT_USERS_PAGE_SIZE = 100;

function assertPasswordPolicy(password: string): void {
  if (password.length < PASSWORD_POLICY.MIN_LENGTH) {
    throw new Error(`Password must be at least ${PASSWORD_POLICY.MIN_LENGTH} characters`);
  }
  if (password.length > PASSWORD_POLICY.MAX_LENGTH) {
    throw new Error(`Password must be at most ${PASSWORD_POLICY.MAX_LENGTH} characters`);
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
    throw new Error("Password must include uppercase and lowercase letters");
  }
  if (!/[0-9]/.test(password)) {
    throw new Error("Password must include at least one number");
  }
  if (!PASSWORD_POLICY.SPECIAL_CHAR_PATTERN.test(password)) {
    throw new Error("Password must include at least one special character");
  }
}

/** Long-lived Auth ban used for deactivate (cleared with ban_duration: "none"). */
const AUTH_BAN_DURATION = "876600h";

const EMAIL_ALREADY_IN_USE =
  "This email is already in use, including inactive accounts. Reactivate the existing account instead of inviting again.";

/**
 * Allowed redirect origins for auth emails (invite / password reset).
 * Configurable via ALLOWED_REDIRECT_ORIGINS (comma-separated). Defaults to the
 * known app origins. Staff-supplied `redirectTo` must match one of these or it
 * is dropped (Supabase Auth also has its own allowlist, but we validate here
 * to fail closed before the email is even queued).
 */
const ALLOWED_REDIRECT_ORIGINS: string[] = (
  Deno.env.get("ALLOWED_REDIRECT_ORIGINS") ||
  [
    "https://tickets.emergentfestival.xyz",
    "https://ticket.emergentfestival.xyz",
    "https://tix.emergentfestival.xyz",
    "https://tics.emergentfestival.xyz",
    // Cloudflare Pages production + preview / branch aliases (Direct Upload).
    "https://ticket-platform.pages.dev",
  ].join(",")
)
  .split(",")
  .map((s) => s.trim().replace(/\/+$/, ""))
  .filter(Boolean);

/** `https://<alias>.ticket-platform.pages.dev` (preview / branch deploys). */
const PAGES_PREVIEW_ORIGIN =
  /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?\.ticket-platform\.pages\.dev$/i;

function isAllowedRedirectOrigin(origin: string): boolean {
  if (ALLOWED_REDIRECT_ORIGINS.includes(origin)) return true;
  return PAGES_PREVIEW_ORIGIN.test(origin);
}

function resolveAllowedRedirect(redirectTo: unknown): string | undefined {
  if (typeof redirectTo !== "string") return undefined;
  const trimmed = redirectTo.trim();
  if (!trimmed) return undefined;
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return undefined;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return undefined;
  const origin = `${u.protocol}//${u.host}`;
  if (!isAllowedRedirectOrigin(origin)) return undefined;
  return trimmed;
}

function resolveDisplayName(email: string, metadata: Record<string, unknown> | null | undefined): string {
  const displayName = metadata?.display_name || metadata?.full_name || metadata?.name;

  if (typeof displayName === "string" && displayName.trim().length > 0) {
    return displayName.trim().slice(0, 100);
  }

  return email.split("@")[0].slice(0, 100);
}

function isDuplicateEmailError(error: { message?: string } | null | undefined): boolean {
  const message = (error?.message ?? "").toLowerCase();
  return (
    message.includes("already been registered") ||
    message.includes("already registered") ||
    message.includes("already exists") ||
    message.includes("users_email_key") ||
    message.includes("duplicate key")
  );
}

async function setAuthBan(supabaseAdmin: SupabaseAdminClient, userId: string, banned: boolean): Promise<void> {
  const { error } = await supabaseAdmin.auth.admin.updateUserById(userId, {
    ban_duration: banned ? AUTH_BAN_DURATION : "none",
  });
  if (error) throw error;
}

async function signOutUserSessions(supabaseAdmin: SupabaseAdminClient, userId: string): Promise<void> {
  try {
    // Scope global signs out all refresh tokens for the user (admin API).
    await supabaseAdmin.auth.admin.signOut(userId, "global");
  } catch (e) {
    console.error("signOutUserSessions failed (non-fatal)", e);
  }
}

async function enqueueAdminPasswordChangedEmail(
  supabaseAdmin: SupabaseAdminClient,
  opts: { userId: string; email: string; displayName: string },
): Promise<void> {
  if (!opts.email) return;
  try {
    const { error } = await supabaseAdmin.from("notification_logs").insert({
      channel: "email",
      recipient: opts.email,
      subject: "管理員已更改密碼 Password updated by admin — 緊急飛 Emergent Tickets",
      template_name: "password-changed-by-admin",
      user_id: opts.userId,
      reference_type: "user",
      reference_id: opts.userId,
      status: "queued",
      provider: "aws_ses",
      payload: {
        display_name: opts.displayName || opts.email.split("@")[0],
      },
      attempt_count: 0,
      max_attempts: 3,
      next_attempt_at: hkNow(),
    });
    if (error) console.error("Failed to enqueue password-changed email:", error);
  } catch (e) {
    console.error("enqueueAdminPasswordChangedEmail failed", e);
  }
}

async function setUserActive(supabaseAdmin: SupabaseAdminClient, userId: string, actorId: string, active: boolean): Promise<void> {
  const { data: existingUser, error: existingError } = await supabaseAdmin
    .from("users")
    .select("display_name, email")
    .eq("id", userId)
    .maybeSingle();
  if (existingError) throw existingError;

  const { data: authResult } = await supabaseAdmin.auth.admin.getUserById(userId);
  const authUser = authResult?.user ?? null;
  if (!existingUser && !authUser) {
    throw new Error("User not found");
  }

  const email = existingUser?.email || authUser?.email || "";
  const displayName = existingUser?.display_name ?? resolveDisplayName(email, authUser?.user_metadata);

  if (existingUser) {
    // Deactivation must not touch the platform role: the authoritative grant lives in
    // platform_staff, which this action never changes.
    const { error: updateError } = await supabaseAdmin
      .from("users")
      .update({ is_active: active, updated_by: actorId })
      .eq("id", userId);
    if (updateError) throw updateError;
  } else {
    // Repair path for an auth user with no public.users row (the handle_new_auth_user
    // trigger normally prevents this). Profile rows carry no role column any more
    // (Phase 7); a buyer is simply the absence of a platform_staff row, so nothing is
    // granted here.
    const { error: insertError } = await supabaseAdmin.from("users").insert({
      id: userId,
      email: email || `unknown-${userId.slice(0, 8)}@local`,
      display_name: displayName,
      is_active: active,
      updated_by: actorId,
    });
    if (insertError) throw insertError;
  }

  await setAuthBan(supabaseAdmin, userId, !active);
  if (!active) {
    await signOutUserSessions(supabaseAdmin, userId);
  }

  await logAuditAction(supabaseAdmin, actorId, userId, active ? "user_activated" : "user_deactivated", {
    is_active: active,
    auth_banned: !active,
  });
}

type SortField = "display_name" | "role" | "account_state" | "created_at";
type SortOrder = "asc" | "desc";
type StatusFilter = "all" | "active" | "inactive" | "pending";

interface AdminUserOrganizationRef {
  id: string;
  name: string;
  role: string | null;
}

interface MergedUser {
  id: string;
  email: string;
  display_name: string;
  /** Platform role only; `null` is a buyer (D12). */
  role: PlatformRole | null;
  created_at: string;
  updated_at: string | null;
  updated_by: string | null;
  updated_by_display_name: string | null;
  updated_by_email: string | null;
  last_sign_in_at: string | null;
  is_active: boolean;
  account_state: string;
  source: "staff" | "non_staff" | "auth_only";
  /**
   * Active organization memberships (open stints only), supplied by
   * `admin_list_users`. Present on `list_users` rows; absent elsewhere.
   */
  organizations?: AdminUserOrganizationRef[];
}

interface UserMetrics {
  total: number;
  admin: number;
  maintainer: number;
  /** Any platform role. */
  staff: number;
  /** No platform_staff row. */
  non_staff: number;
}

interface ListUsersQuery {
  page: number;
  pageSize: number;
  sortField: SortField;
  sortOrder: SortOrder;
  role: "all" | AccountType;
  status: StatusFilter;
  search: string;
  /** Structured organization filter — active memberships only. `null` = no filter. */
  organizationId: string | null;
  /**
   * "Has any active organization membership" facet. Deliberately kept off the `role`
   * channel: `scopeListQueryForCaller` rewrites `role` to `non_staff` for a maintainer,
   * so an overloaded value would be silently dropped. As its own flag it composes
   * (non_staff AND hasOrganization).
   */
  hasOrganization: boolean;
}

interface AdminListUsersRpcResult {
  users: MergedUser[];
  totalCount: number;
  metrics: UserMetrics;
  page: number;
  pageSize: number;
  sortField: SortField;
  sortOrder: SortOrder;
}

interface UserMembership {
  role: string;
  is_active: boolean;
  invited_at: string | null;
  invitation_accepted_at: string | null;
  organization: {
    id: string;
    name: string;
    instagram: string | null;
    is_active: boolean;
  };
}

interface UserStats {
  ticketCount: number;
  orderCount: number;
}

/** `public.users` row — the columns the admin merge path reads. */
interface PublicUserRow {
  id: string;
  email: string;
  display_name: string;
  is_active: boolean;
  created_at: string | null;
  updated_at: string | null;
  updated_by: string | null;
}

/**
 * The subset of the Supabase auth user (`auth.admin.getUserById`) the merge path
 * reads. Structural rather than importing the SDK's `User` so this Deno build does
 * not depend on a named type re-export of the esm.sh bundle.
 */
interface AuthUserLike {
  id: string;
  email?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  last_sign_in_at?: string | null;
  confirmed_at?: string | null;
  email_confirmed_at?: string | null;
  banned_until?: string | null;
  user_metadata?: Record<string, unknown> | null;
}

/** The updater columns the roster embeds (`display_name`, `email`). */
interface PublicUserUpdaterRef {
  display_name: string;
  email: string;
}

/** An `organization_members` row with its `organizations` embed, per the select below. */
interface MembershipJoinRow {
  role: string;
  is_active: boolean;
  invited_at: string | null;
  invitation_accepted_at: string | null;
  organizations: {
    id: string;
    name: string;
    instagram: string | null;
    is_active: boolean;
  } | null;
}

function normalizeSearchTerm(query: string): string {
  return query
    .toLowerCase()
    .trim()
    .replace(/[(),*%]/g, "");
}

function isSortField(value: unknown): value is SortField {
  return value === "display_name" || value === "role" || value === "account_state" || value === "created_at";
}

/**
 * Shape check only — the value is passed to Postgres as a `uuid` parameter, so an
 * invalid value would raise rather than match anything. Rejecting it here keeps
 * the failure a clean no-op (no filter) instead of a 500.
 */
function parseOrganizationId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) return null;
  return trimmed;
}

function parseListUsersQuery(payload: Record<string, unknown> | null | undefined): ListUsersQuery {
  const rawPage = Number(payload?.page ?? 1);
  const rawPageSize = Number(payload?.pageSize ?? 15);
  const page = Number.isFinite(rawPage) && rawPage > 0 ? Math.floor(rawPage) : 1;
  const pageSize = Number.isFinite(rawPageSize) ? Math.min(100, Math.max(1, Math.floor(rawPageSize))) : 15;

  const sortField = isSortField(payload?.sortField) ? payload.sortField : "created_at";
  const rawOrder = payload?.sortOrder;
  const sortOrder: SortOrder =
    rawOrder === "ascend" || rawOrder === "asc" ? "asc" : rawOrder === "descend" || rawOrder === "desc" ? "desc" : sortField === "created_at" ? "desc" : "asc";

  // The list's role chips are exclusive, so the "organization" facet arrives on the role
  // channel. It is an org relationship rather than a platform role, so it is split out
  // here — passing it to `normalizeAccountType` would throw.
  const rawRole = typeof payload?.role === "string" ? payload.role : "all";
  const hasOrganization = rawRole === "organization";
  const role = rawRole === "all" || hasOrganization ? "all" : normalizeAccountType(rawRole);
  const status =
    payload?.status === "active" || payload?.status === "inactive" || payload?.status === "pending" ? payload.status : "all";
  const search = typeof payload?.search === "string" ? normalizeSearchTerm(payload.search) : "";
  const organizationId = parseOrganizationId(payload?.organizationId);

  return { page, pageSize, sortField, sortOrder, role, status, search, organizationId, hasOrganization };
}

function assertDisplayName(displayName: unknown): string {
  if (typeof displayName !== "string") {
    throw new Error("Display name must be a string");
  }
  const trimmed = displayName.trim();
  if (trimmed.length < 1 || trimmed.length > 100) {
    throw new Error("Display name must be 1-100 characters");
  }
  return trimmed;
}

async function callAdminListUsers(supabaseAdmin: SupabaseAdminClient, query: ListUsersQuery): Promise<AdminListUsersRpcResult> {
  const { data, error } = await supabaseAdmin.rpc("admin_list_users", {
    p_search: query.search,
    p_role: query.role,
    p_status: query.status,
    p_page: query.page,
    p_page_size: query.pageSize,
    p_sort_field: query.sortField,
    p_sort_order: query.sortOrder,
    p_organization_id: query.organizationId,
    p_has_organization: query.hasOrganization,
  });

  if (error) throw error;

  const result = (data ?? {}) as Partial<AdminListUsersRpcResult>;
  return {
    users: Array.isArray(result.users) ? result.users : [],
    totalCount: typeof result.totalCount === "number" ? result.totalCount : 0,
    metrics: result.metrics ?? { total: 0, admin: 0, maintainer: 0, staff: 0, non_staff: 0 },
    page: typeof result.page === "number" ? result.page : query.page,
    pageSize: typeof result.pageSize === "number" ? result.pageSize : query.pageSize,
    sortField: isSortField(result.sortField) ? result.sortField : query.sortField,
    sortOrder: result.sortOrder === "asc" || result.sortOrder === "desc" ? result.sortOrder : query.sortOrder,
  };
}

function resolveUpdaterFields(
  updatedBy: string | null | undefined,
  publicUsersById: Map<string, PublicUserUpdaterRef> | undefined,
): Pick<MergedUser, "updated_by" | "updated_by_display_name" | "updated_by_email"> {
  const updaterId = updatedBy || null;
  const updater = updaterId ? publicUsersById?.get(updaterId) : null;
  return {
    updated_by: updaterId,
    updated_by_display_name: updater?.display_name || null,
    updated_by_email: updater?.email || null,
  };
}

function mergePublicAndAuthUser(
  publicUser: PublicUserRow | null,
  authUser: AuthUserLike | null,
  publicUsersById?: Map<string, PublicUserUpdaterRef>,
  platformRole: PlatformRole | null = null,
): MergedUser | null {
  if (publicUser) {
    const email = publicUser.email || authUser?.email || "";
    const isActive = publicUser.is_active !== false;
    let accountState = "pending";
    if (!isActive) accountState = "inactive";
    else if (authUser?.confirmed_at || authUser?.email_confirmed_at) accountState = "active";
    else accountState = "pending";

    return {
      id: publicUser.id,
      email,
      display_name: publicUser.display_name || resolveDisplayName(email, authUser?.user_metadata),
      role: platformRole,
      created_at: publicUser.created_at || authUser?.created_at || hkNow(),
      updated_at: publicUser.updated_at || authUser?.updated_at || null,
      ...resolveUpdaterFields(publicUser.updated_by, publicUsersById),
      last_sign_in_at: authUser?.last_sign_in_at || null,
      is_active: isActive,
      account_state: accountState,
      source: platformRole ? "staff" : "non_staff",
    };
  }

  if (authUser) {
    const email = authUser.email || "";
    const banned = Boolean(authUser.banned_until);
    return {
      id: authUser.id,
      email,
      display_name: resolveDisplayName(email, authUser.user_metadata),
      role: platformRole,
      created_at: authUser.created_at || hkNow(),
      updated_at: authUser.updated_at || null,
      updated_by: null,
      updated_by_display_name: null,
      updated_by_email: null,
      last_sign_in_at: authUser.last_sign_in_at || null,
      is_active: !banned,
      account_state: banned ? "inactive" : authUser.confirmed_at || authUser.email_confirmed_at ? "active" : "pending",
      // No public.users row — incomplete; not the same as a buyer with a profile.
      source: "auth_only",
    };
  }

  return null;
}

async function resolveMergedUser(supabaseAdmin: SupabaseAdminClient, userId: string): Promise<MergedUser | null> {
  const [{ data: publicUser, error: publicError }, authResult, platformRole] = await Promise.all([
    supabaseAdmin.from("users").select("*").eq("id", userId).maybeSingle(),
    supabaseAdmin.auth.admin.getUserById(userId),
    loadPlatformRole(supabaseAdmin, userId),
  ]);

  if (publicError) throw publicError;

  const authUser = authResult?.data?.user ?? null;
  if (authResult?.error && !publicUser) {
    throw authResult.error;
  }

  let publicUsersById: Map<string, PublicUserUpdaterRef> | undefined;
  const updaterId = publicUser?.updated_by as string | null | undefined;
  if (updaterId) {
    const { data: updater } = await supabaseAdmin
      .from("users")
      .select("id, display_name, email")
      .eq("id", updaterId)
      .maybeSingle();
    if (updater) {
      publicUsersById = new Map([[updater.id, updater]]);
    }
  }

  return mergePublicAndAuthUser(publicUser, authUser, publicUsersById, platformRole);
}

async function loadUserMemberships(supabaseAdmin: SupabaseAdminClient, userId: string): Promise<UserMembership[]> {
  const { data, error } = await supabaseAdmin
    .from("organization_members")
    .select(
      "role, is_active, invited_at, invitation_accepted_at, organizations(id, name, instagram, is_active)",
    )
    .eq("user_id", userId);

  if (error) throw error;

  return (data ?? [])
    .map((row: MembershipJoinRow) => {
      const org = row.organizations;
      if (!org?.id) return null;
      return {
        role: row.role,
        is_active: row.is_active !== false,
        invited_at: row.invited_at ?? null,
        invitation_accepted_at: row.invitation_accepted_at ?? null,
        organization: {
          id: org.id,
          name: org.name ?? "",
          instagram: org.instagram ?? null,
          is_active: org.is_active !== false,
        },
      } satisfies UserMembership;
    })
    .filter(Boolean) as UserMembership[];
}

async function loadUserStats(supabaseAdmin: SupabaseAdminClient, userId: string): Promise<UserStats> {
  const [ticketResult, orderResult] = await Promise.all([
    supabaseAdmin.from("tickets").select("*", { count: "exact", head: true }).eq("user_id", userId),
    supabaseAdmin.from("orders").select("*", { count: "exact", head: true }).eq("user_id", userId),
  ]);

  if (ticketResult.error) throw ticketResult.error;
  if (orderResult.error) throw orderResult.error;

  return {
    ticketCount: ticketResult.count ?? 0,
    orderCount: orderResult.count ?? 0,
  };
}

async function exportUsers(supabaseAdmin: SupabaseAdminClient, query: ListUsersQuery): Promise<MergedUser[]> {
  const users: MergedUser[] = [];
  let page = 1;

  while (users.length < EXPORT_USERS_MAX) {
    const result = await callAdminListUsers(supabaseAdmin, {
      ...query,
      page,
      pageSize: EXPORT_USERS_PAGE_SIZE,
    });

    if (result.users.length === 0) break;

    users.push(...result.users);

    if (users.length >= result.totalCount || result.users.length < EXPORT_USERS_PAGE_SIZE) {
      break;
    }

    page += 1;
  }

  return users.slice(0, EXPORT_USERS_MAX);
}

/** Helpers */
async function logAuditAction(supabaseAdmin: SupabaseAdminClient, adminId: string, entityId: string, action: string, details: Record<string, unknown> = {}, reason?: string) {
  try {
    const { error } = await supabaseAdmin.from("audit_logs").insert({
      user_id: adminId,
      category: "admin",
      entity_type: "user",
      entity_id: entityId,
      action,
      changes: details,
      reason: reason ?? null,
    });
    if (error) console.error("Audit log error:", error);
  } catch (e) {
    console.error("Failed to log audit action", e);
  }
}

serve(async (req) => {
  // Handle CORS
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

    // Initialize Supabase client with admin privileges
    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { action, payload } = await req.json();

    // Public: precheck for password recovery flow.
    // Returns an indistinguishable response for all outcomes (active, inactive,
    // not found) so an unauthenticated caller cannot enumerate which emails
    // exist or were deactivated. The actual inactive-account block is enforced
    // server-side at sign-in (AuthProvider enforceActiveAccount + RLS), not here.
    // Throttling is handled separately (see SECURITY_AUDIT M14).
    if (action === "precheck_recovery") {
      const email = typeof payload?.email === "string" ? payload.email.trim().toLowerCase() : "";
      if (!email) throw new Error("Email is required");

      const { data: row, error: emailError } = await supabaseAdmin
        .from("users")
        .select("id, is_active")
        .ilike("email", email)
        .maybeSingle();
      if (emailError) throw emailError;

      // Always allow at this layer; inactive users who reset their password are
      // still blocked from signing in by enforceActiveAccount.
      void row;
      return new Response(JSON.stringify({ success: true, allowed: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    // Verify caller has a valid token
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      throw new Error("Missing Authorization header");
    }

    const token = authHeader.replace("Bearer ", "");
    const {
      data: { user: caller },
      error: authError,
    } = await supabaseAdmin.auth.getUser(token);

    if (authError || !caller) {
      throw new Error("Invalid token or user not found");
    }

    // Authoritative platform-staff check: public.platform_staff (never users.role,
    // never user_metadata). Absence of a row means a buyer with no platform access.
    const { data: callerRecord, error: callerError } = await supabaseAdmin.from("users").select("is_active").eq("id", caller.id).maybeSingle();
    const callerPlatformRole = await loadPlatformRole(supabaseAdmin, caller.id);

    const isPlatformAdmin = callerPlatformRole === "admin";
    // `maintainer` is an ops-writer: it runs day-to-day platform work, manages NON-STAFF
    // accounts and owns full organization management, but platform staff identities are
    // invisible and immutable to it. Every staff boundary below is enforced here (the
    // client-side gate is cosmetic) and mirrored in SQL by `users_admin_select`,
    // `admin_list_users` and `admin_global_search`.
    const isPlatformStaff = isPlatformAdmin || callerPlatformRole === "maintainer";

    if (callerError || !callerRecord || !isPlatformStaff) {
      throw new Error("Unauthorized: Only platform staff can manage users");
    }
    if (callerRecord.is_active === false) {
      throw new Error("Unauthorized: caller account is inactive");
    }

    /**
     * A maintainer may neither read nor mutate an admin/maintainer account. Admins are
     * unrestricted. This is the single choke point for every write below, so a new action
     * added later cannot forget it.
     */
    const assertTargetIsNotStaff = async (targetUserId: string): Promise<void> => {
      if (isPlatformAdmin) return;
      if ((await loadPlatformRole(supabaseAdmin, targetUserId)) !== null) {
        throw new Error("Unauthorized: Only platform admins can view or modify platform staff accounts");
      }
    };

    const assertCanAssignRole = (targetRole: AccountType) => {
      if (isPlatformAdmin) return;
      // A maintainer may only ever write "non_staff" — i.e. no platform role at all. The
      // platform role is forced to buyer/absent on anything a maintainer writes, so
      // granting (or re-granting) admin/maintainer is admin-only.
      if (targetRole === "admin" || targetRole === "maintainer") {
        throw new Error("Unauthorized: Only platform admins can grant or change a platform role");
      }
    };

    /**
     * The RPC call below runs as service_role (the edge has already authenticated the
     * caller and scopes the result itself), so its service_role branch returns staff rows
     * and full staff counters. For a maintainer the request is narrowed to the non-staff
     * set at the SQL level — which keeps pagination and `totalCount` correct — and the
     * staff counters are then zeroed so the admin headcount never leaks.
     *
     * Staff role chips (`admin` / `maintainer`) must NOT be rewritten to `non_staff`:
     * that made `role=admin` look like an unfiltered non-staff page (F7). Maintainers
     * cannot see staff, so those filters are an empty page — matching JWT-scoped
     * `admin_list_users(p_role='admin')`.
     */
    const scopeListQueryForCaller = (query: ListUsersQuery): ListUsersQuery =>
      isPlatformAdmin ? query : { ...query, role: "non_staff" };

    const staffRoleFilterEmptyForMaintainer = (query: ListUsersQuery): boolean =>
      !isPlatformAdmin && (query.role === "admin" || query.role === "maintainer");

    const emptyMaintainerListResult = (query: ListUsersQuery): AdminListUsersRpcResult => ({
      users: [],
      totalCount: 0,
      metrics: { total: 0, admin: 0, maintainer: 0, staff: 0, non_staff: 0 },
      page: query.page,
      pageSize: query.pageSize,
      sortField: query.sortField,
      sortOrder: query.sortOrder,
    });

    const scopeListResultForCaller = (result: AdminListUsersRpcResult): AdminListUsersRpcResult => {
      if (isPlatformAdmin) return result;
      return {
        ...result,
        // belt-and-braces: the SQL filter already excluded these
        users: result.users.filter((row) => row.source !== "staff"),
        metrics: {
          total: result.metrics.non_staff,
          admin: 0,
          maintainer: 0,
          staff: 0,
          non_staff: result.metrics.non_staff,
        },
      };
    };

    if (action === "list_users") {
      const parsed = parseListUsersQuery(payload ?? {});
      const result = staffRoleFilterEmptyForMaintainer(parsed)
        ? emptyMaintainerListResult(parsed)
        : scopeListResultForCaller(await callAdminListUsers(supabaseAdmin, scopeListQueryForCaller(parsed)));

      return new Response(
        JSON.stringify({
          success: true,
          users: result.users,
          metrics: result.metrics,
          totalCount: result.totalCount,
          page: result.page,
          pageSize: result.pageSize,
          sortField: result.sortField,
          sortOrder: result.sortOrder === "asc" ? "ascend" : "descend",
        }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 200,
        },
      );
    }

    if (action === "export_users") {
      // Scoped at the SQL level, so a maintainer's export can never contain a staff row.
      const parsed = parseListUsersQuery(payload ?? {});
      if (staffRoleFilterEmptyForMaintainer(parsed)) {
        return new Response(JSON.stringify({ success: true, users: [] }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 200,
        });
      }
      const query = scopeListQueryForCaller(parsed);
      const users = await exportUsers(supabaseAdmin, query);

      return new Response(JSON.stringify({ success: true, users }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "get_user") {
      const userId = payload?.userId;
      if (!userId || typeof userId !== "string") {
        throw new Error("User ID is required");
      }

      // A staff target is reported as absent rather than forbidden, so a maintainer cannot
      // even confirm that an admin/maintainer account exists.
      if (!isPlatformAdmin && (await loadPlatformRole(supabaseAdmin, userId)) !== null) {
        return new Response(JSON.stringify({ success: false, error: "User not found" }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 404,
        });
      }

      const user = await resolveMergedUser(supabaseAdmin, userId);
      if (!user) {
        return new Response(JSON.stringify({ success: false, error: "User not found" }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 404,
        });
      }

      const [memberships, stats] = await Promise.all([
        loadUserMemberships(supabaseAdmin, userId),
        loadUserStats(supabaseAdmin, userId),
      ]);

      return new Response(JSON.stringify({ success: true, user: { ...user, memberships, stats } }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "invite_user") {
      const { email, role, organizationId, memberRole, redirectTo } = payload;
      if (!email) {
        throw new Error("Email is required");
      }

      // Absent role means "buyer" — the UI no longer sends a customer literal, but a
      // stale build may, and normalizeAccountType folds it onto non_staff.
      const accountType: AccountType = role === undefined || role === null || role === "" ? "non_staff" : normalizeAccountType(role);
      assertCanAssignRole(accountType);

      // Flow A (admin assign): the membership is written directly, with no acceptance
      // step, which is why organizationId is required to attach one. It is also the only
      // path that can introduce an email that does not exist yet (Flow B requires an
      // existing user). The member role is validated here rather than defaulted silently.
      const attachesMembership = organizationId !== undefined && organizationId !== null && organizationId !== "";
      if (attachesMembership && memberRole !== undefined && memberRole !== null && memberRole !== "" && memberRole !== "owner" && memberRole !== "manager") {
        throw new Error("memberRole must be 'owner' or 'manager'");
      }
      const normalizedMemberRole = memberRole === "owner" ? "owner" : "manager";

      const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
      const { data: existingPublic } = await supabaseAdmin.from("users").select("id").ilike("email", normalizedEmail).maybeSingle();
      if (existingPublic) {
        throw new Error(EMAIL_ALREADY_IN_USE);
      }

      // 1. Invite auth user. `role` is deliberately NOT put in user_metadata: metadata is
      //    never authoritative for authorization, and a stale copy there is a trap.
      //
      // `must_set_password: true` is required: inviteUserByEmail creates a session from the
      // email link with no usable password. The SPA forces `/update-password` until the
      // flag is cleared; otherwise the invitee only sees the terms gate and later cannot
      // password-login (forgot-password only).
      //
      // If the staff-supplied redirect is not on the allowlist, still land on set-password
      // on a known origin — dropping redirectTo would use the project Site URL and skip
      // the password form.
      const inviteRedirect =
        resolveAllowedRedirect(redirectTo) ??
        resolveAllowedRedirect("https://develop.ticket-platform.pages.dev/update-password") ??
        resolveAllowedRedirect("https://ticket-platform.pages.dev/update-password");
      const { data: authData, error: inviteError } = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
        data: {
          display_name: email.split("@")[0],
          must_set_password: true,
        },
        redirectTo: inviteRedirect,
      });

      if (inviteError) {
        if (isDuplicateEmailError(inviteError)) {
          throw new Error(EMAIL_ALREADY_IN_USE);
        }
        throw inviteError;
      }

      const newUserId = authData.user.id;
      const displayName = (email.split("@")[0] || "User").slice(0, 100);

      // handle_new_auth_user already inserted the profile row; this upsert only fills
      // in the display name + attribution, and must not carry a role.
      const { data: userData, error: createUserError } = await supabaseAdmin
        .from("users")
        .upsert(
          {
            id: newUserId,
            email,
            display_name: displayName,
            updated_by: caller.id,
          },
          { onConflict: "id" },
        )
        .select()
        .single();

      if (createUserError) {
        await supabaseAdmin.auth.admin.deleteUser(newUserId);
        if (isDuplicateEmailError(createUserError)) {
          throw new Error(EMAIL_ALREADY_IN_USE);
        }
        throw createUserError;
      }

      if (accountType !== "non_staff") {
        await setPlatformRole(supabaseAdmin, newUserId, accountType, caller.id);
      }

      if (attachesMembership) {
        const { error: memberError } = await supabaseAdmin.from("organization_members").insert({
          organization_id: organizationId,
          user_id: newUserId,
          role: normalizedMemberRole,
          invited_by: caller.id,
        });
        if (memberError) {
          await supabaseAdmin.auth.admin.deleteUser(newUserId);
          throw memberError;
        }
      }

      await logAuditAction(supabaseAdmin, caller.id, newUserId, accountType === "non_staff" ? "invite_customer" : "invite_user", {
        email,
        role: accountType,
        organizationId: organizationId ?? null,
        memberRole: attachesMembership ? normalizedMemberRole : null,
        redirectTo,
      });

      return new Response(JSON.stringify({ success: true, data: userData }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "update_user") {
      const { userId, role, newPassword, displayName } = payload;
      if (!userId) throw new Error("User ID is required");

      const requestedAccountType: AccountType | null = role === undefined || role === null || role === "" ? null : normalizeAccountType(role);

      // Cannot change own role from here to prevent locking self out
      if (userId === caller.id && requestedAccountType !== null && requestedAccountType !== callerPlatformRole) {
        throw new Error("Cannot change your own platform role from this panel");
      }

      const { data: targetUser } = await supabaseAdmin
        .from("users")
        .select("email, display_name, is_active")
        .eq("id", userId)
        .maybeSingle();

      const targetPlatformRole = await loadPlatformRole(supabaseAdmin, userId);
      await assertTargetIsNotStaff(userId);
      if (requestedAccountType !== null) assertCanAssignRole(requestedAccountType);

      // Never demote the last active admin: the platform has no way back in, which is the
      // same shape as D31's zero-owner organization. The self-change guard above already
      // makes this nearly unreachable; this is the assertion, not the mechanism.
      if (targetPlatformRole === "admin" && requestedAccountType !== "admin") {
        const activeAdmins = await countActiveAdmins(supabaseAdmin);
        if (activeAdmins <= 1) {
          throw new Error("Cannot remove the last platform admin");
        }
      }

      const normalizedDisplayName = displayName !== undefined && displayName !== null ? assertDisplayName(displayName) : null;
      const displayNameChanged = normalizedDisplayName !== null && normalizedDisplayName !== (targetUser?.display_name ?? "");

      // Update Auth password if provided — never for deactivated accounts (no notify email either)
      if (newPassword) {
        if (targetUser?.is_active === false) {
          throw new Error("Cannot change password for an inactive account. Activate the account first.");
        }
        assertPasswordPolicy(newPassword);
        const { error: pwdError } = await supabaseAdmin.auth.admin.updateUserById(userId, { password: newPassword });
        if (pwdError) throw pwdError;
        await signOutUserSessions(supabaseAdmin, userId);
        const notifyEmail = targetUser?.email || "";
        await enqueueAdminPasswordChangedEmail(supabaseAdmin, {
          userId,
          email: notifyEmail,
          displayName: normalizedDisplayName ?? targetUser?.display_name ?? resolveDisplayName(notifyEmail, null),
        });
      }

      if (normalizedDisplayName !== null) {
        const { error: displayNameError } = await supabaseAdmin
          .from("users")
          .update({ display_name: normalizedDisplayName, updated_by: caller.id })
          .eq("id", userId);
        if (displayNameError) throw displayNameError;

        const { error: metadataError } = await supabaseAdmin.auth.admin.updateUserById(userId, {
          user_metadata: { display_name: normalizedDisplayName },
        });
        if (metadataError) throw metadataError;
      }

      // Platform role lives in platform_staff. Deliberately NOT written to
      // users.role (retired in Phase 7) or to user_metadata.role (never authoritative).
      if (requestedAccountType !== null) {
        await setPlatformRole(supabaseAdmin, userId, requestedAccountType, caller.id);

        // D9: a role change is decoupled from organization membership. Demoting a
        // staff member used to DELETE their organization_members row, which destroyed
        // the record that they had ever been a member — re-enabling them was then
        // impossible and the org silently lost its manager. Membership is now only ever
        // changed by an explicit member action (soft-disable, D23).
      } else if (newPassword && normalizedDisplayName === null) {
        // Password-only admin action still attributes last updater on the public profile when present
        await supabaseAdmin.from("users").update({ updated_by: caller.id }).eq("id", userId);
      }

      await logAuditAction(supabaseAdmin, caller.id, userId, "update_user", {
        role: requestedAccountType,
        password_changed: !!newPassword,
        display_name_changed: displayNameChanged,
      });

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "send_password_reset") {
      const { userId, redirectTo } = payload ?? {};
      if (!userId) throw new Error("User ID is required");

      const { data: targetUser, error: targetError } = await supabaseAdmin
        .from("users")
        .select("id, email, is_active")
        .eq("id", userId)
        .maybeSingle();
      if (targetError) throw targetError;
      if (!targetUser) throw new Error("User not found");
      await assertTargetIsNotStaff(userId);
      if (targetUser.is_active === false) {
        throw new Error("Cannot send password reset to an inactive account. Activate the account first.");
      }
      if (!targetUser.email) throw new Error("User has no email address");

      const { error: resetError } = await supabaseAdmin.auth.resetPasswordForEmail(targetUser.email, {
        redirectTo: resolveAllowedRedirect(redirectTo),
      });
      if (resetError) throw resetError;

      await logAuditAction(supabaseAdmin, caller.id, userId, "send_password_reset", { email: targetUser.email });

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "suspend_user" || action === "set_user_active") {
      const { userId, status, isActive } = payload;
      if (!userId) throw new Error("User ID is required");
      if (userId === caller.id) throw new Error("Cannot deactivate your own admin account");

      await assertTargetIsNotStaff(userId);

      const active = action === "set_user_active" ? isActive !== false : status === "active";
      await setUserActive(supabaseAdmin, userId, caller.id, active);

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "close_user" || action === "delete_user") {
      const { userId } = payload;
      if (!userId) throw new Error("User ID is required");

      if (userId === caller.id) {
        throw new Error("Cannot deactivate your own admin account");
      }

      await assertTargetIsNotStaff(userId);

      await setUserActive(supabaseAdmin, userId, caller.id, false);

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "bulk_set_user_active") {
      const { userIds, isActive } = payload;
      if (!userIds || !Array.isArray(userIds) || userIds.length === 0) throw new Error("userIds array is required");

      if (isActive === false && userIds.includes(caller.id)) {
        throw new Error("Cannot deactivate your own admin account");
      }

      const results = [];
      const errors = [];

      for (const userId of userIds) {
        try {
          await assertTargetIsNotStaff(userId);
          await setUserActive(supabaseAdmin, userId, caller.id, isActive !== false);
          results.push(userId);
        } catch (e) {
          errors.push({ userId, error: (e as Error).message });
        }
      }

      return new Response(JSON.stringify({ success: errors.length === 0, results, errors }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    if (action === "bulk_close_users" || action === "bulk_delete_users") {
      const { userIds } = payload;
      if (!userIds || !Array.isArray(userIds) || userIds.length === 0) throw new Error("userIds array is required");

      if (userIds.includes(caller.id)) {
        throw new Error("Cannot deactivate your own admin account");
      }

      const results = [];
      const errors = [];

      for (const userId of userIds) {
        try {
          await assertTargetIsNotStaff(userId);
          await setUserActive(supabaseAdmin, userId, caller.id, false);
          results.push(userId);
        } catch (e) {
          errors.push({ userId, error: (e as Error).message });
        }
      }

      return new Response(JSON.stringify({ success: errors.length === 0, results, errors }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    throw new Error(`Invalid action: ${action}`);
  } catch (error) {
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 400,
    });
  }
});
