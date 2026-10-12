const { createClient } = require("@supabase/supabase-js");
const crypto = require("node:crypto");

const cors = {
  "Access-Control-Allow-Origin": process.env.URL || "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
  "Cache-Control": "no-store"
};
const json = (statusCode, data) => ({ statusCode, headers: cors, body: JSON.stringify(data) });
const service = () => {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error("Server is not configured. Add Supabase environment variables in Netlify.");
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
};
function hashCode(code) { return crypto.createHash("sha256").update(String(code).trim().toUpperCase()).digest("hex"); }
function newCode() { return "AFX-" + crypto.randomBytes(3).toString("hex").toUpperCase() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase(); }
async function authUser(req, adminRequired=false) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) throw Object.assign(new Error("Please sign in first."), { statusCode: 401 });
  const db = service();
  const { data, error } = await db.auth.getUser(token);
  if (error || !data.user) throw Object.assign(new Error("Your session is invalid. Please sign in again."), { statusCode: 401 });
  if (adminRequired) {
    const allow = (process.env.ADMIN_EMAILS || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
    const email = (data.user.email || "").toLowerCase();
    if (!email || !allow.includes(email)) throw Object.assign(new Error("Admin access denied. Add your authenticated email to Netlify ADMIN_EMAILS."), { statusCode: 403 });
  }
  return { db, user: data.user };
}
async function adminLog(db, user, action, detail={}) {
  await db.from("admin_audit").insert({ admin_id: user.id, action, detail });
}
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: cors, body: "" };
  if (event.httpMethod !== "POST") return json(405, { error: "Use POST." });
  let input;
  try { input = JSON.parse(event.body || "{}"); } catch { return json(400, { error: "Invalid JSON." }); }
  try {
    const action = String(input.action || "");
    if (action === "redeem") {
      const { db, user } = await authUser(event, false);
      if (!user.is_anonymous) throw Object.assign(new Error("This account has already been used. Sign out and use a fresh activation code only if you intend to create a new student account."), { statusCode: 400 });
      const name = String(input.name || "").trim().slice(0, 80);
      const code = String(input.code || "").trim().toUpperCase();
      if (name.length < 2 || code.length < 8) throw Object.assign(new Error("Enter your name and a valid activation code."), { statusCode: 400 });
      // Call the SECURITY DEFINER RPC with the student's JWT so auth.uid() inside
      // Postgres is the same user we just verified, rather than the service-role identity.
      if (!process.env.SUPABASE_ANON_KEY) throw new Error("Server is not configured. Add SUPABASE_ANON_KEY to Netlify environment variables.");
      const token = (event.headers.authorization || event.headers.Authorization || "").replace(/^Bearer\\s+/i, "");
      const studentClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
        global: { headers: { Authorization: `Bearer ${token}` } }
      });
      const { data, error } = await studentClient.rpc("redeem_activation_code", { p_code_hash: hashCode(code), p_user_id: user.id, p_display_name: name });
      if (error) throw new Error(error.message.toLowerCase().includes("invalid") ? "That activation code is invalid, expired, or already used. Contact AhmadFX support." : error.message);
      return json(200, { profile: data, user: { id: user.id } });
    }
    if (action === "profile" || action === "student-data" || action === "progress") {
      const { db, user } = await authUser(event, false);
      const { data: profile, error: pErr } = await db.from("profiles").select("id,display_name,expires_at,status,created_at").eq("id", user.id).maybeSingle();
      if (pErr) throw pErr;
      if (action === "profile") return json(200, { profile, user: { id: user.id } });
      if (!profile) throw Object.assign(new Error("No activated student profile found. Enter your activation code first."), { statusCode: 403 });
      if (profile.status !== "active" || (profile.expires_at && new Date(profile.expires_at) < new Date())) throw Object.assign(new Error("Your access has expired or been blocked. Contact AhmadFX support."), { statusCode: 403 });
      if (action === "progress") {
        const courseId = input.course_id;
        if (courseId) {
          const { error } = await db.from("lesson_progress").upsert({ user_id: user.id, course_id: courseId, completed: true, completed_at: new Date().toISOString() }, { onConflict: "user_id,course_id" });
          if (error) throw error;
        }
        return json(200, { ok: true });
      }
      const [{ data: courses, error: cErr }, { data: progress, error: prErr }, { data: analysis, error: aErr }] = await Promise.all([
        db.from("courses").select("id,title,category,description,video_url,published,sort_order").eq("published", true).order("sort_order"),
        db.from("lesson_progress").select("course_id,completed,completed_at").eq("user_id", user.id),
        db.from("market_notes").select("id,title,body,created_at").eq("published", true).order("created_at", { ascending: false }).limit(20)
      ]);
      if (cErr) throw cErr; if (prErr) throw prErr; if (aErr) throw aErr;
      return json(200, { profile, courses: courses || [], progress: progress || [], analysis: analysis || [] });
    }
    if (action === "admin-check") {
      const { user } = await authUser(event, true);
      return json(200, { ok: true, email: user.email });
    }
    if (action === "admin-data") {
      const { db, user } = await authUser(event, true);
      const [{ data: courses, error: ce }, { data: codes, error: co }, { data: students, error: se }, { data: analysis, error: ae }] = await Promise.all([
        db.from("courses").select("*").order("sort_order"),
        db.from("activation_codes").select("id,code_hash,duration_days,status,redeemed_at,created_at,note").order("created_at", { ascending: false }).limit(200),
        db.from("profiles").select("id,display_name,status,expires_at,created_at").order("created_at", { ascending: false }).limit(500),
        db.from("market_notes").select("*").order("created_at", { ascending: false }).limit(50)
      ]);
      if (ce) throw ce; if (co) throw co; if (se) throw se; if (ae) throw ae;
      await adminLog(db, user, "view_admin_data");
      return json(200, {
        courses: courses || [],
        codes: (codes || []).map(c => ({ ...c, code_mask: c.status === "available" ? "Available code ••••••••" : "Activated / revoked ••••••••", code: null })),
        students: students || [], analysis: analysis || []
      });
    }
    if (action === "create-code") {
      const { db, user } = await authUser(event, true);
      const days = Number(input.duration_days);
      if (!Number.isInteger(days) || days < 1 || days > 3650) throw Object.assign(new Error("Validity must be from 1 to 3650 days."), { statusCode: 400 });
      const code = newCode();
      const { data, error } = await db.from("activation_codes").insert({ code_hash: hashCode(code), duration_days: days, status: "available", note: String(input.note || "").slice(0,100), created_by: user.id }).select("id,duration_days,status").single();
      if (error) throw error;
      await adminLog(db, user, "create_activation_code", { code_id: data.id, duration_days: days });
      return json(200, { code, duration_days: days, id: data.id });
    }
    if (action === "revoke-code") {
      const { db, user } = await authUser(event, true);
      const { error } = await db.from("activation_codes").update({ status: "revoked" }).eq("id", input.id).neq("status", "redeemed");
      if (error) throw error;
      await adminLog(db, user, "revoke_activation_code", { code_id: input.id });
      return json(200, { ok: true });
    }
    if (action === "save-course") {
      const { db, user } = await authUser(event, true);
      const title = String(input.title || "").trim().slice(0,160);
      const video = String(input.video_url || "").trim();
      if (!title) throw Object.assign(new Error("A lesson title is required."), { statusCode: 400 });
      if (video && !/^https:\/\//i.test(video)) throw Object.assign(new Error("Video links must use HTTPS."), { statusCode: 400 });
      const payload = { title, category: String(input.category || "Beginner").slice(0,60), description: String(input.description || "").slice(0,1200), video_url: video || null, published: Boolean(input.published), updated_at: new Date().toISOString() };
      let result;
      if (input.id) result = await db.from("courses").update(payload).eq("id", input.id).select("id").single();
      else result = await db.from("courses").insert({ ...payload, sort_order: Date.now() }).select("id").single();
      if (result.error) throw result.error;
      await adminLog(db, user, "save_course", { course_id: result.data.id });
      return json(200, { ok: true, id: result.data.id });
    }
    if (action === "save-analysis") {
      const { db, user } = await authUser(event, true);
      const title = String(input.title || "").trim().slice(0,140), body = String(input.body || "").trim().slice(0,6000);
      if (!title || !body) throw Object.assign(new Error("Title and study note are required."), { statusCode: 400 });
      const { error } = await db.from("market_notes").insert({ title, body, published: true, created_by: user.id });
      if (error) throw error;
      await adminLog(db, user, "publish_market_note", { title });
      return json(200, { ok: true });
    }
    if (action === "extend-student") {
      const { db, user } = await authUser(event, true);
      const days = Number(input.days);
      if (!Number.isInteger(days) || days < 1 || days > 3650) throw Object.assign(new Error("Enter between 1 and 3650 days."), { statusCode: 400 });
      const { data: p, error: pe } = await db.from("profiles").select("expires_at").eq("id", input.id).single();
      if (pe) throw pe;
      const base = p.expires_at && new Date(p.expires_at) > new Date() ? new Date(p.expires_at) : new Date();
      base.setDate(base.getDate() + days);
      const { error } = await db.from("profiles").update({ expires_at: base.toISOString(), status: "active" }).eq("id", input.id);
      if (error) throw error;
      await adminLog(db, user, "extend_student", { student_id: input.id, days });
      return json(200, { ok: true });
    }
    if (action === "block-student") {
      const { db, user } = await authUser(event, true);
      const { error } = await db.from("profiles").update({ status: "blocked" }).eq("id", input.id);
      if (error) throw error;
      await adminLog(db, user, "block_student", { student_id: input.id });
      return json(200, { ok: true });
    }
    return json(404, { error: "Unknown action." });
  } catch (err) {
    const status = err.statusCode || 400;
    console.error("AhmadFX API error:", err.message);
    return json(status, { error: err.message || "Request failed." });
  }
};
