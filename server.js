import "dotenv/config";

import express from "express";
import cors from "cors";
import multer from "multer";
import path from "path";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import cron from "node-cron";
import { createClient } from "@supabase/supabase-js";
import * as pdfjsLib from "pdfjs-dist/legacy/build/pdf.js";


import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);


const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE environment variables");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);

process.env.PDFJS_NO_CMAP = "true";
process.env.PDFJS_NO_STANDARD_FONTS = "true";

const app = express();

// ---------------------------------------------
// CORS
// ---------------------------------------------
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ✅ IMPORTANT: handle preflight requests
app.options("*", cors());


const DB_SCHEMA = `
Tables and columns:

records:
- id (bigint)
- pr_no (text)
- work_name (text)
- record_type (text)
- amount (numeric)
- status (text)
- pr_status (text)
- division_label (text)
- sub_division (text)
- send_to (text)
- firm_name (text)
- po_no (text)
- budget_head (text)
- pr_date (text)
- pr_date2 (text)
- pdf_url (text)
- page_no (text)
- remarks (text)
- high_value_spares (text)
- pending_with (text)
- responsible_officer (text)
- last_updated_by (text)
- last_updated_at (timestamp)
- created_at (timestamp)
- is_deleted (boolean)

estimates:
- id (bigint)
- pr_no (text)
- estimate_no (text)
- description (text)
- division_label (text)
- po_no (text)
- gross_amount (numeric)
- net_amount (numeric)
- loa_no (text)
- sap_billing_doc (text)
- mb_no (text)
- page_no (text)
- back_charging (text)
- start_date (date)
- status (text)
- created_at (timestamp)

daily_progress:
- id (bigint)
- date (date)
- activity (text)
- manpower (text)
- status (text)
- division_label (text)
- table_html (text)
- row_count (integer)
- created_at (timestamp)

cl_biodata:
- id (bigint)
- name (text)
- gender (text)
- aadhar (text)
- phone (text)
- station (text)
- division (text)
- doj (text)
- dob (text)
- wages (numeric)
- nominee (text)
- relation (text)
- photo_url (text)
- created_at (timestamp)

pending_users:
- id (bigint)
- name (text)
- reason (text)
- created_at (timestamp)
`;


// ---------------------------------------------
// EMAIL SETUP
// ---------------------------------------------
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

import { fileURLToPath } from "url";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

// ---------------------------------------------
// AUTHENTICATION MIDDLEWARE (same JWT logic)
// ---------------------------------------------
const JWT_SECRET = "810632";

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ---------------------------------------------
// MULTER MEMORY STORAGE (for Supabase upload)
// ---------------------------------------------
const uploadInMemory = multer({ storage: multer.memoryStorage() });

// ---------------------------------------------
// MIDDLEWARE
// ---------------------------------------------
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ---------------------------------------------
// HELPERS: map DB rows -> frontend shape
// ---------------------------------------------


function mapDailyRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    date: row.date,
    tableHTML: row.table_html,
    rowCount: row.row_count,
    createdAt: row.created_at,
  };
}

// =================================================================
// RECORD ROUTES (use Supabase instead of data.json)
// =================================================================

// Get all non-deleted records
app.get("/records", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("records")
      .select("*")
      .eq("is_deleted", false)
      .order("id", { ascending: false });

    if (error) throw error;

    const mapped = data.map(mapRecordRow);
    res.json(mapped);
  } catch (err) {
    console.error("GET /records error:", err);
    res.status(500).json({ error: "Failed to load records" });
  }
});

// Get trash (deleted records)
app.get("/records/trash", authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("records")
      .select("*")
      .eq("is_deleted", true)
      .order("id", { ascending: false });

    if (error) throw error;

    // frontend expects deletedOn, so just reuse created_at
    const mapped = data.map((row) => ({
      ...mapRecordRow(row),
      deletedOn: row.created_at,
    }));

    res.json(mapped);
  } catch (err) {
    console.error("GET /records/trash error:", err);
    res.status(500).json({ error: "Failed to load trash" });
  }
});

// ---------------------------------------------------------
// PDF UPLOAD to Supabase Storage (replaces Cloudinary + JSON)
// ---------------------------------------------------------
// ---------------------------------------------------------
// PDF UPLOAD to Supabase Storage
// ---------------------------------------------------------
const PDF_BUCKET = "pdfs";

app.post(
  "/upload",
  authenticateToken,
  uploadInMemory.array("pdfs", 10),
  async (req, res) => {
    try {
      const {
        id,
        workName,
        prNo,
        subDivision,
        recordType,
        amount,
        sendTo,
        pdfPath,
        status,
        // new fields
        prDate,
        budgetHead,
        poNo,
        prDate2,
        firmName,
        divisionLabel,
        pageNo,
        remarks,
        highValueSpares
      } = req.body;

const cleanAmount =
  typeof amount === "string"
    ? Number(amount.replace(/,/g, "")) || 0
    : amount || 0;

      
      let newPdfUrl = null;

      // upload PDF
      if (req.files && req.files.length > 0) {
        const file = req.files[0];

        const ext = path.extname(file.originalname) || ".pdf";
        const uniqueName =
          Date.now() + "_" + Math.random().toString(36).slice(2) + ext;

        const { data: uploadData, error: uploadError } =
          await supabase.storage.from(PDF_BUCKET).upload(uniqueName, file.buffer, {
            contentType: file.mimetype || "application/pdf",
            upsert: false,
          });

        if (uploadError) {
          console.error("Upload Error:", uploadError);
          return res.status(500).json({ error: "Failed to upload PDF" });
        }

        newPdfUrl = supabase.storage
          .from(PDF_BUCKET)
          .getPublicUrl(uploadData.path).data.publicUrl;
      }

      const finalPdfUrl = newPdfUrl || pdfPath || null;

    

      // ---------------------------------
      // UPDATE
      // ---------------------------------
      if (id) {
        const updatePayload = {
          work_name: workName || null,
          pr_no: prNo || null,
          sub_division: subDivision || null,
          record_type: recordType || null,
          amount: cleanAmount,
          send_to: sendTo || null,
          status: status || null,
          pr_date: prDate || null,
          budget_head: budgetHead || null,
          po_no: poNo || null,
          pr_date2: prDate2 || null,
          firm_name: firmName || null,
          division_label: divisionLabel || null,
          page_no: pageNo || null,
          remarks: remarks || null,
          high_value_spares: highValueSpares || null,
        };

        if (newPdfUrl) updatePayload.pdf_url = newPdfUrl;

        const { data, error } = await supabase
          .from("records")
          .update(updatePayload)
          .eq("id", Number(id))
          .select("*");

        if (error) throw error;

        return res.json({ success: true, record: mapRecordRow(data[0]) });
      }

      // ---------------------------------
      // INSERT
      // ---------------------------------
      const insertPayload = {
        work_name: workName || null,
        pr_no: prNo || null,
        sub_division: subDivision || null,
        record_type: recordType || "Other Record",
        amount: cleanAmount,
        send_to: sendTo || null,
        status: status || 'Pending',
        pdf_url: finalPdfUrl,
        is_deleted: false,
        pr_date: prDate || null,
        budget_head: budgetHead || null,
        po_no: poNo || null,
        pr_date2: prDate2 || null,
        firm_name: firmName || null,
        division_label: divisionLabel || null,
        page_no: pageNo || null,
        remarks: remarks || null,
        high_value_spares: highValueSpares || null,
      };

      const { data, error } = await supabase
        .from("records")
        .insert(insertPayload)
        .select("*");

      if (error) throw error;

      return res.json({ success: true, record: mapRecordRow(data[0]) });

    } catch (err) {
      console.error("UPLOAD ROUTE ERROR:", err);
      res.status(500).json({ error: "Upload failed" });
    }
  }
); // ←← THIS WAS MISSING

// Move to trash
app.delete("/records/:id", authenticateToken, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const { error } = await supabase
      .from("records")
      .update({ is_deleted: true })
      .eq("id", id);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /records/:id error:", err);
    res.status(500).json({ error: "Failed to move to trash" });
  }
});

// Restore from trash
app.post("/records/:id/restore", authenticateToken, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const { error } = await supabase
      .from("records")
      .update({ is_deleted: false })
      .eq("id", id);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("RESTORE /records/:id error:", err);
    res.status(500).json({ error: "Failed to restore record" });
  }
});

// Permanent delete + remove file from storage
app.delete("/records/trash/:id", authenticateToken, async (req, res) => {
  const id = Number(req.params.id);

  try {
    // 1. Find record
    const { data, error } = await supabase
      .from("records")
      .select("*")
      .eq("id", id)
      .single();

    if (error && error.code !== "PGRST116") throw error;
    if (!data) return res.status(404).json({ error: "Not found" });

    // 2. If PDF exists, delete from storage
    if (data.pdf_url) {
      try {
        const urlObj = new URL(data.pdf_url);
        const idx = urlObj.pathname.indexOf(`/object/public/${PDF_BUCKET}/`);
        if (idx !== -1) {
          const relativePath = urlObj.pathname.substring(
            idx + `/object/public/${PDF_BUCKET}/`.length
          );
          await supabase.storage.from(PDF_BUCKET).remove([relativePath]);
        }
      } catch (parseErr) {
        console.warn("Failed to parse PDF URL for delete:", parseErr);
      }
    }

    // 3. Delete row
    const { error: delError } = await supabase
      .from("records")
      .delete()
      .eq("id", id);

    if (delError) throw delError;

    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /records/trash/:id error:", err);
    res.status(500).json({ error: "Failed to permanently delete record" });
  }
});

// =================================================================
// PDF TEXT EXTRACTION (unchanged, still uses pdfjs-dist)
// =================================================================

app.post(
  "/extract-pdf",
  authenticateToken,
  uploadInMemory.single("pdfFile"),
  async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No PDF uploaded" });

    try {
      const loadingTask = pdfjsLib.getDocument({ data: req.file.buffer });
      const pdf = await loadingTask.promise;

      let extractedText = "";

      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        extractedText += content.items.map((i) => i.str).join(" ") + "\n";
      }

      const text = extractedText.replace(/\s+/g, " ").trim();

      const prNoMatch = text.match(/PR\s*No\.?\s*[:\-]?\s*(\d+)/i);
      const amountMatch = text.match(/Estimated\s*Value\s*[:\-]?\s*([0-9,]+)/i);
      const divisionMatch = text.match(/Division\s*:? ?([A-Za-z0-9\-]+)/i);
      const briefMatch = text.match(/Brief Description[:\-]?\s*(.+?)(?= Estimate| PR|$)/i);

      res.json({
        prNo: prNoMatch ? prNoMatch[1] : "",
        workName: briefMatch ? briefMatch[1] : "",
        amount: amountMatch ? amountMatch[1].replace(/,/g, "") : "",
        subDivision: divisionMatch ? divisionMatch[1] : "",
        recordType: "PR",
      });
    } catch (err) {
      console.error("PDF extract error:", err);
      res.status(500).json({ error: "Failed to extract PDF" });
    }
  }
);

/* ============================================================
      ESTIMATES API — ADD / LIST / EDIT / TRASH
============================================================ */

/* -------------------------------------------
   CREATE NEW ESTIMATE
-------------------------------------------- */
app.post("/estimates", async (req, res) => {
  try {
    const data = req.body;

    const { error } = await supabase.from("estimates").insert(data);

    if (error) throw error;

    res.json({ success: true, message: "Estimate saved successfully" });
  } catch (err) {
    console.error("Error saving estimate:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------------------------
   GET ALL ESTIMATES (ACTIVE ONLY)
-------------------------------------------- */
app.get("/estimates", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("estimates")
      .select("*")
      .eq("is_deleted", false)
      .order("id", { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error("Error fetching estimates:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------------------------
   GET TRASH ESTIMATES
-------------------------------------------- */
app.get("/estimates/trash", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("estimates")
      .select("*")
      .eq("is_deleted", true)
      .order("id", { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error("Error fetching trash:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------------------------
   UPDATE / EDIT ESTIMATE
-------------------------------------------- */
app.put("/estimates/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const data = req.body;

    const { error } = await supabase
      .from("estimates")
      .update(data)
      .eq("id", id);

    if (error) throw error;

    res.json({ success: true, message: "Estimate updated successfully" });
  } catch (err) {
    console.error("Error updating estimate:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------------------------
   SOFT DELETE (MOVE TO TRASH)
-------------------------------------------- */
app.delete("/estimates/:id", async (req, res) => {
  try {
    const id = req.params.id;

    const { error } = await supabase
      .from("estimates")
      .update({ is_deleted: true })
      .eq("id", id);

    if (error) throw error;

    res.json({ success: true, message: "Moved to trash" });
  } catch (err) {
    console.error("Error deleting estimate:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------------------------
   RESTORE FROM TRASH (OPTIONAL)
-------------------------------------------- */
app.post("/estimates/restore/:id", async (req, res) => {
  try {
    const id = req.params.id;

    const { error } = await supabase
      .from("estimates")
      .update({ is_deleted: false })
      .eq("id", id);

    if (error) throw error;

    res.json({ success: true, message: "Record restored" });
  } catch (err) {
    console.error("Restore error:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------------------------
   HARD DELETE (PERMANENT) — OPTIONAL
-------------------------------------------- */
app.delete("/estimates/remove/:id", async (req, res) => {
  try {
    const id = req.params.id;

    const { error } = await supabase
      .from("estimates")
      .delete()
      .eq("id", id);

    if (error) throw error;

    res.json({ success: true, message: "Permanently deleted" });
  } catch (err) {
    console.error("Hard delete error:", err);
    res.status(500).json({ error: err.message });
  }
});



// =================================================================
// DAILY PROGRESS ROUTES (Supabase instead of daily.json)
// =================================================================

// Get all snapshots
app.get("/daily-progress", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("daily_progress")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json(data.map(mapDailyRow));
  } catch (err) {
    console.error("GET /daily-progress error:", err);
    res.status(500).json({ error: "Failed to load daily progress" });
  }
});

// Get one snapshot
app.get("/daily-progress/:id", async (req, res) => {
  const id = Number(req.params.id);
  try {
    const { data, error } = await supabase
      .from("daily_progress")
      .select("*")
      .eq("id", id)
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Not found" });

    res.json(mapDailyRow(data));
  } catch (err) {
    console.error("GET /daily-progress/:id error:", err);
    res.status(500).json({ error: "Failed to load snapshot" });
  }
});

app.post("/page-visit/:page", async (req, res) => {
  try {
    const page = req.params.page.trim();

    const { data, error } = await supabase
      .from("page_visits")
      .upsert(
        {
          page_name: page,
          visit_count: 1,
          last_visited: new Date().toISOString()
        },
        { onConflict: "page_name" }
      )
      .select();

    if (error) {
      console.error("Upsert error:", error);
      return res.status(500).json({ error: "Upsert failed" });
    }

    // If row already existed, increment manually
    if (data && data.length > 0) {
      await supabase
        .from("page_visits")
        .update({
          visit_count: data[0].visit_count + 1,
          last_visited: new Date().toISOString()
        })
        .eq("page_name", page);
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Visit error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/page-visit/:page", async (req, res) => {
  const page = req.params.page.trim();

  const { data, error } = await supabase
    .from("page_visits")
    .select("visit_count")
    .eq("page_name", page)
    .single();

  if (error) {
    return res.json({ count: 0 });
  }

  res.json({ count: data.visit_count });
});

// Create / update snapshot
app.post("/daily-progress", authenticateToken, async (req, res) => {
  const { id, date, tableHTML, rowCount } = req.body;

  try {
    const payload = {
      date,
      table_html: tableHTML,
      row_count: rowCount,
    };

    if (id) {
      // UPDATE
      const { error } = await supabase
        .from("daily_progress")
        .update(payload)
        .eq("id", id);

      if (error) throw error;
    } else {
      // INSERT
      const { error } = await supabase
        .from("daily_progress")
        .insert(payload);

      if (error) throw error;
    }

    res.json({ success: true, message: "Snapshot saved" });

  } catch (err) {
    console.error("POST /daily-progress error:", err);
    res.status(500).json({ error: "Failed to save snapshot" });
  }
});


// Delete snapshot
app.delete("/daily-progress/:id", authenticateToken, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const { error } = await supabase
      .from("daily_progress")
      .delete()
      .eq("id", id);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /daily-progress/:id error:", err);
    res.status(500).json({ error: "Failed to delete snapshot" });
  }
});
// =================================================================
// DAILY PROGRESS - BATCH IMPORT (Excel upload)
// =================================================================
app.post("/daily-progress/batch-import", authenticateToken, async (req, res) => {
  try {
    const snapshots = req.body;  // array of { date, tableHTML, rowCount }

    if (!Array.isArray(snapshots)) {
      return res.status(400).json({ error: "Invalid data format" });
    }

    for (const snap of snapshots) {
      // check existing snapshot for date
      const { data: existing } = await supabase
        .from("daily_progress")
        .select("*")
        .eq("date", snap.date)
        .maybeSingle();

      if (existing) {
        // update
        await supabase
          .from("daily_progress")
          .update({
            table_html: snap.tableHTML,
            row_count: snap.rowCount
          })
          .eq("id", existing.id);
      } else {
        // insert new
        await supabase
          .from("daily_progress")
          .insert({
            date: snap.date,
            table_html: snap.tableHTML,
            row_count: snap.rowCount
          });
      }
    }

    res.json({ success: true, message: "Batch import completed!" });

  } catch (err) {
    console.error("Batch import error:", err);
    res.status(500).json({ error: "Batch import failed" });
  }
});


// =================================================================
// USER AUTH (store users in Supabase table, JWT handled here)
// =================================================================

let pendingVerifications = {};

app.post("/register-send-otp", async (req, res) => {
  try {
    const { email, password, inviteCode } = req.body;

    if (!email || !password || inviteCode !== "810632") {
      return res.status(400).json({ message: "Invalid data" });
    }

    // Check if user already exists
    const { data: existing, error: checkError } = await supabase
      .from("users")
      .select("id")
      .eq("email", email);

    if (checkError) throw checkError;
    if (existing && existing.length > 0) {
      return res.status(409).json({ message: "Already registered" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const passwordHash = await bcrypt.hash(password, 10);

    pendingVerifications[email] = {
      email,
      passwordHash,
      otp,
      expires: Date.now() + 10 * 60 * 1000,
    };

    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject: "Verification Code",
      text: `Your OTP is ${otp}`,
    });

    res.json({ message: "OTP sent" });
  } catch (err) {
    console.error("register-send-otp error:", err);
    res
      .status(500)
      .json({ message: "Email sending or DB check failed", error: err.toString() });
  }
});

app.post("/register-verify", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const pending = pendingVerifications[email];
    if (!pending || pending.otp !== otp || pending.expires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    const { error } = await supabase.from("users").insert({
      email,
      password_hash: pending.passwordHash,
    });

    if (error) throw error;

    delete pendingVerifications[email];

    res.json({ message: "Registration complete" });
  } catch (err) {
    console.error("register-verify error:", err);
    res.status(500).json({ message: "Registration failed", error: err.toString() });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Get user from Supabase
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // 2. Check password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect password." });
    }

    // 3. Create JWT token ✅
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    // 4. Send token back to frontend ✅
    return res.json({
      message: "Login successful",
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// =================================================================
// STATIC FILES
// =================================================================
app.use(express.static(__dirname, { extensions: ["html"] }));

// =================================================================
// CL BIO DATA ROUTES (with Supabase Storage Upload)
// =================================================================

const CL_BUCKET = "cl-photos";   // FIXED BUCKET NAME

app.post(
  "/cl",
  authenticateToken,
  uploadInMemory.single("photo"),   // FIXED FIELD NAME
  async (req, res) => {
    try {
      const {
        id,
        name,
        gender,
        aadhar,
        phone,
        station,
        division,
        doj,
        dob,
        wages,
        nominee,
        relation,
        photo_url // existing URL if editing
      } = req.body;

      let newPhotoUrl = null;

      if (req.file) {
        const ext = path.extname(req.file.originalname) || ".jpg";
        const uniqueName = Date.now() + "_" + Math.random().toString(36).slice(2) + ext;

        const { data: uploadData, error: uploadErr } = await supabase.storage
          .from(CL_BUCKET)
          .upload(uniqueName, req.file.buffer, {
            contentType: req.file.mimetype,
          });

        if (uploadErr) throw uploadErr;

        const { data: urlData } = supabase.storage
          .from(CL_BUCKET)
          .getPublicUrl(uploadData.path);

        newPhotoUrl = urlData.publicUrl;
      }

      const finalPhoto = newPhotoUrl || photo_url || null;

      const payload = {
        name,
        gender,
        aadhar,
        phone,
        station,
        division,
        doj,
        dob,
        wages,
        nominee,
        relation,
        photo_url: finalPhoto
      };

      let result;

      if (id) {
        const { data, error } = await supabase
          .from("cl_biodata")
          .update(payload)
          .eq("id", id)
          .select("*");
        if (error) throw error;
        result = data[0];
      } else {
        const { data, error } = await supabase
          .from("cl_biodata")
          .insert(payload)
          .select("*");
        if (error) throw error;
        result = data[0];
      }

      res.json({ success: true, cl: result });

    } catch (err) {
      console.error("CL SAVE ERROR:", err);
      res.status(500).json({ error: "Failed to save CL" });
    }
  }
);

app.post(
  "/file-transfer/upload",
  authenticateToken,
  uploadInMemory.array("files", 10),
  async (req, res) => {
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No files uploaded" });
      }

      const results = [];

      for (const file of req.files) {
        const ext = path.extname(file.originalname);
        const fileName = `${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`;
        const storagePath = `uploads/${fileName}`;

        const { error } = await supabase.storage
          .from("file-transfer")
          .upload(storagePath, file.buffer, {
            contentType: file.mimetype
          });

        if (error) throw error;

        const fileUrl = supabase.storage
          .from("file-transfer")
          .getPublicUrl(storagePath).data.publicUrl;

        const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);

        await supabase.from("file_transfers").insert({
          file_name: file.originalname,
          file_path: storagePath,
          file_url: fileUrl,
          file_size: file.size,
          uploaded_by: req.user.email,
          expires_at: expiresAt
        });

        results.push(file.originalname);
      }

      res.json({ success: true, uploaded: results });

    } catch (err) {
      console.error("Multi upload error:", err);
      res.status(500).json({ error: "Upload failed" });
    }
  }
);

app.get("/file-transfer", async (req, res) => {
  try {
    const now = new Date().toISOString();

    const { data, error } = await supabase
      .from("file_transfers")
      .select("*")
      .gt("expires_at", now)
      .order("uploaded_at", { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Failed to load files" });
  }
});
app.delete(
  "/file-transfer/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data, error } = await supabase
        .from("file_transfers")
        .select("*")
        .eq("id", id)
        .single();

      if (!data || error) {
        return res.status(404).json({ error: "File not found" });
      }

      await supabase.storage
        .from("file-transfer")
        .remove([data.file_path]);

      await supabase
        .from("file_transfers")
        .delete()
        .eq("id", id);

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: "Delete failed" });
    }
  }
);
cron.schedule("0 * * * *", async () => {
  const now = new Date().toISOString();

  const { data } = await supabase
    .from("file_transfers")
    .select("*")
    .lt("expires_at", now);

  for (const file of data || []) {
    await supabase.storage
      .from("file-transfer")
      .remove([file.file_path]);

    await supabase
      .from("file_transfers")
      .delete()
      .eq("id", file.id);
  }

  console.log("Expired file transfers cleaned");
});

// GET all CL data
app.get("/cl", async (req, res) => {
  try {
    const { data, error } = await supabase.from("cl_biodata").select("*").order("id");
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("GET /cl ERROR:", err);
    res.status(500).json({ error: "Failed to load CL data" });
  }
});

// DELETE CL
app.delete("/cl/:id", authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { error } = await supabase.from("cl_biodata").delete().eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("DELETE CL ERROR:", err);
    res.status(500).json({ error: "Failed to delete CL" });
  }
});

// ================= AI MEMORY =================
app.get("/ai/memory", authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("ai_learning")   // ✅ CORRECT TABLE
      .select("*")
      .order("id", { ascending: true });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("AI memory error:", err);
    res.status(500).json([]);
  }
});


app.get("/api/remarks/:pr", async (req, res) => {
  try {
    const { pr } = req.params;

    const { data, error } = await supabase
      .from("remarks")
      .select("*")
      .eq("pr_no", pr)
      .order("created_at", { ascending: true });

    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error("GET remarks error:", err);
    res.status(500).json({ error: "Failed to load remarks" });
  }
});


app.post("/api/remarks", authenticateToken, async (req, res) => {
  try {
    const { pr_no, text } = req.body;

    if (!pr_no || !text) {
      return res.status(400).json({ error: "Missing pr_no or text" });
    }

    const { error } = await supabase
      .from("remarks")
      .insert({
        pr_no,
        text,
        by: req.user.email
      });

    if (error) throw error;

    res.json({ success: true });
  } catch (err) {
    console.error("POST remarks error:", err);
    res.status(500).json({ error: "Failed to save remark" });
  }
});

app.post("/ai/learn", authenticateToken, async (req, res) => {
  const { rawText, module, extracted, corrected } = req.body;

  await supabase.from("ai_learning").insert({
    raw_text: rawText,
    module,
    extracted,
    corrected
  });

  res.json({ success: true });
});

function mapEstimateRow(row) {
  if (!row) return null;

  return {
    id: row.id,
    prNo: row.prNo,
    estimateNo: row.estimateNo,
    description: row.description,
    division: row.division,
    poNo: row.poNo,
    grossAmount: row.grossAmount,
    netAmount: row.netAmount,
    loaNo: row.loaNo,
    billingDoc: row.billingDoc,
    mbookNo: row.mbookNo,
    regPg: row.regPg,
    backCharging: row.backCharging,
    dates: row.dates,
    status: row.status,
    createdAt: row.created_at
  };
}

app.get("/ai/search/estimates", async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  const { data, error } = await supabase
    .from("estimates")
    .select("*")
    .ilike("description", `%${q}%`)
    .limit(1);

  if (error) return res.status(500).json({ error: error.message });

  res.json(data.map(mapEstimateRow));
});


function mapRecordRow(row) {
  if (!row) return null;

  return {
    // 🔑 Identifiers
    id: row.id,
    prNo: row.pr_no,

    // 📄 Core PR data
    workName: row.work_name,
    recordType: row.record_type,
    amount: row.amount,

    // ✅ Status
    status: row.status,           // Pending / Completed
    prStatus: row.pr_status,      // PR Created / Sent etc.

    // 🏢 Classification
    divisionLabel: row.division_label,
    subDivision: row.sub_division,
    sendTo: row.send_to,

    // 🏭 Vendor / PO
    firmName: row.firm_name,
    poNo: row.po_no,
    budgetHead: row.budget_head,

    // 📅 Dates
    prDate: row.pr_date,
    prDate2: row.pr_date2,

    // 📄 Document
    pdfPath: row.pdf_url,
    pageNo: row.page_no,
    remarks: row.remarks,
    highValueSpares: row.high_value_spares,

    // 👤 Responsibility
    pendingWith: row.pending_with,
    responsibleOfficer: row.responsible_officer,
    lastUpdatedBy: row.last_updated_by,
    lastUpdatedAt: row.last_updated_at,

    // 🕒 System
    createdAt: row.created_at,
    isDeleted: row.is_deleted
  };
}



app.get("/ai/search/records", async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  const { data, error } = await supabase
    .from("records")
    .select("*")
    .eq("is_deleted", false)   // ✅ CRITICAL
    .or(`pr_no.ilike.%${q}%,work_name.ilike.%${q}%`)
    .limit(1);

  if (error) {
    console.error("AI search records error:", error);
    return res.status(500).json([]);
  }

  res.json(data.map(mapRecordRow));
});


function mapDailyAIRow(row) {
  return {
    id: row.id,
    date: row.date,
    tableHTML: row.table_html,
    rowCount: row.row_count,
    createdAt: row.created_at
  };
}

app.get("/ai/search/daily", async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  const { data, error } = await supabase
    .from("daily_progress")
    .select("*")
    .ilike("activity", `%${q}%`)
    .limit(1);

  if (error) return res.status(500).json({ error: error.message });

  res.json(data.map(mapDailyAIRow));
});

function mapCLRow(row) {
  return {
    id: row.id,
    name: row.name,
    gender: row.gender,
    aadhar: row.aadhar,
    phone: row.phone,
    station: row.station,
    division: row.division,
    doj: row.doj,
    dob: row.dob,
    wages: row.wages,
    nominee: row.nominee,
    relation: row.relation,
    photoUrl: row.photo_url,
    createdAt: row.created_at
  };
}


const TABLES = {
  records: "records",
  estimates: "estimates",
  daily: "daily_progress",
  cl: "cl_biodata",
  users: "users",
  pending: "pending_users",
  documents: "pr_documents",
  remarks: "pr_remarks"
};




app.get("/ai/search/cl", async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  const { data, error } = await supabase
    .from("cl_biodata")
    .select("*")
    .or(`name.ilike.%${q}%,aadhar.ilike.%${q}%`)
    .limit(1);

  if (error) return res.status(500).json({ error: error.message });

  res.json(data.map(mapCLRow));
});

function mapFileRow(row) {
  return {
    id: row.id,
    fileName: row.file_name,
    fileUrl: row.file_url,
    uploadedBy: row.uploaded_by,
    expiresAt: row.expires_at
  };
}


function buildPlannerPrompt(question) {
  return `
You are an AI that converts user questions into database query plans.

Database schema:
${DB_SCHEMA}

Rules:
- Output ONLY valid JSON
- No explanations
- No markdown
- No extra text
- Never invent tables or columns
- Use only schema above

JSON format:
{
  "table": "table_name",
  "columns": ["column_name"] | ["*"],
  "filters": {
    "column": "value"
  },
  "limit": 1
}

Rules for columns:
- If user asks for a specific field, include ONLY that column
- If user asks for full / complete / all details, use ["*"]

If question is NOT about database, respond:
{ "type": "general" }

User question:
"${question}"
`;
}


/*
app.post("/ai/query", async (req, res) => {
  try {
    const question = (req.body.text || "").trim();
    if (!question) {
      return res.json({ reply: "Please ask a question." });
    }

    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash"
    });

    const prompt = buildPlannerPrompt(question);
    const result = await model.generateContent(prompt);
    const raw = result.response.text().trim();

    let plan;
    try {
      plan = JSON.parse(raw);
    } catch {
      return res.json({ reply: "I could not understand the query clearly." });
    }

    // Non-DB question
   if (plan.type === "general") {
  // Ask AI normally (no planner, no schema)
  const chatModel = genAI.getGenerativeModel({
    model: "gemini-2.5-flash"
  });

  const chatResult = await chatModel.generateContent(
    `User: ${question}\nAI:`
  );

  return res.json({
    reply: chatResult.response.text().trim()
  });
}


    // Validate table
    const allowedTables = [
      "records",
      "estimates",
      "daily_progress",
      "cl_biodata",
      "pending_users"
    ];

    if (!allowedTables.includes(plan.table)) {
      return res.json({ reply: "Invalid table requested." });
    }

    // Build SELECT
    const selectCols =
      plan.columns && plan.columns.includes("*")
        ? "*"
        : (plan.columns || ["*"]).join(",");

    let query = supabase
      .from(plan.table)
      .select(selectCols);

    // Filters
    if (plan.filters) {
      for (const [col, val] of Object.entries(plan.filters)) {
        query = query.eq(col, val);
      }
    }

    const limit = plan.limit && plan.limit <= 20 ? plan.limit : 1;
    const { data, error } = await query.limit(limit);

    if (error) {
      console.error(error);
      return res.json({ reply: "Database query failed." });
    }

    if (!data || data.length === 0) {
      return res.json({ reply: "No matching data found." });
    }

    return res.json({
      reply: "Here is the requested information.",
      table: plan.table,
      columns: plan.columns || ["*"],
      data
    });

  } catch (err) {
    console.error("AI QUERY ERROR:", err);
    return res.json({ reply: "Service temporarily unavailable." });
  }
}); */

function detectIntent(text) {
  const t = text.toLowerCase().trim();

  /* ---------------- GREETING ---------------- */
  if (/\b(hi|hello|hey|good morning|good evening)\b/.test(t)) {
    return { type: "GREETING" };
  }

  /* ---------------- DIVISION ---------------- */
  const divMatch = t.match(/\b(tm&cam|em|c&i|mm|stage[-\s]?v|sd[-\s]?iv)\b/i);
  const division = divMatch ? divMatch[0].toUpperCase() : null;

  /* ---------------- DATE ---------------- */
  const dateMatch =
    t.match(/\b\d{2}[-/]\d{2}[-/]\d{4}\b/) ||
    t.match(/\b\d{4}-\d{2}-\d{2}\b/);
  const date = dateMatch ? dateMatch[0] : null;

  /* ---------------- PR ---------------- */
  const prMatch = t.match(/\b10\d{8}\b/);
  if (prMatch) {
    const prNo = prMatch[0];

    // single column requests
    if (t.includes("date")) {
      return { type: "PR_COLUMN", column: "pr_date", prNo };
    }
    if (t.includes("status")) {
      return { type: "PR_COLUMN", column: "status", prNo };
    }
    if (t.includes("amount") || t.includes("value")) {
      return { type: "PR_COLUMN", column: "amount", prNo };
    }

    // full PR details
    return { type: "PR_FULL", prNo };
  }

  /* ---------------- ESTIMATE ---------------- */
  
   const estMatch = t.match(/\b(13|21)\d{8}\b/);
  if (estMatch) {
    return { type: "ESTIMATE_FULL", estimateNo: estMatch[0] };
  }

  /* ---------------- DAILY PROGRESS ---------------- */
  if (t.includes("daily")) {
    return { type: "DAILY_LIST", division, date };
  }

  /* ---------------- CL BIO DATA ---------------- */
  const aadMatch = t.match(/\b\d{12}\b/);
  if (aadMatch) {
    return { type: "CL_FULL", aadhar: aadMatch[0] };
  }

  if (t.includes("cl")) {
    return { type: "CL_LIST", division };
  }

  /* ---------------- FALLBACK ---------------- */
  return { type: "UNKNOWN" };
}





app.get("/dashboard/summary", authenticateToken, async (req, res) => {
  const [prs, ests, daily, cls] = await Promise.all([
    supabase.from("records").select("*", { count: "exact", head: true }),
    supabase.from("estimates").select("*", { count: "exact", head: true }),
    supabase.from("daily_progress").select("*", { count: "exact", head: true }),
    supabase.from("cl_biodata").select("*", { count: "exact", head: true })
  ]);

  res.json({
    records: prs.count,
    estimates: ests.count,
    daily_progress: daily.count,
    cl_biodata: cls.count
  });
});



app.post("/ai/query", async (req, res) => {
  try {
    const question = (req.body.query || "").trim();
    if (!question) {
      return res.json({ reply: "Ask something." });
    }

    const intent = detectIntent(question);

    // GREETING
    if (intent.type === "GREETING") {
      return res.json({ reply: "Hello 👋 How can I help you?" });
    }

    // PR FULL
    if (intent.type === "PR_FULL") {
      const { data, error } = await supabase
        .from("records")
        .select("*")
        .eq("pr_no", intent.prNo)
        .limit(1);

      if (error) throw error;
      if (!data || !data.length) {
        return res.json({ reply: "PR not found." });
      }

      return res.json({
        reply: `Details for PR ${intent.prNo}`,
        columns: Object.keys(data[0]),
        data
      });
    }

    // PR COLUMN
    if (intent.type === "PR_COLUMN") {
      const { data, error } = await supabase
        .from("records")
        .select(intent.column)
        .eq("pr_no", intent.prNo)
        .limit(1);

      if (error) throw error;
      if (!data || !data.length) {
        return res.json({ reply: "PR not found." });
      }

      return res.json({
        reply: `${intent.column.replace("_", " ")}: ${data[0][intent.column]}`
      });
    }

    // ESTIMATE
    if (intent.type === "ESTIMATE_FULL") {
      const { data, error } = await supabase
        .from("estimates")
        .select("*")
        .or(
          `estimate_no.eq.${intent.estimateNo},pr_no.eq.${intent.estimateNo}`
        )
        .limit(1);

      if (error) throw error;
      if (!data || !data.length) {
        return res.json({ reply: "Estimate not found." });
      }

      return res.json({
        reply: `Estimate ${intent.estimateNo}`,
        columns: Object.keys(data[0]),
        data
      });
    }

    // DAILY
    if (intent.type === "DAILY_LIST") {
      let q = supabase
        .from("daily_progress")
        .select("*")
        .order("date", { ascending: false });

      if (intent.division) q = q.eq("division", intent.division);

      const { data, error } = await q.limit(5);
      if (error) throw error;

      return res.json({
        reply: "Daily progress records:",
        columns: data.length ? Object.keys(data[0]) : [],
        data
      });
    }

    // CL FULL
    if (intent.type === "CL_FULL") {
      const { data, error } = await supabase
        .from("cl_biodata")
        .select("*")
        .eq("aadhar", intent.aadhar)
        .limit(1);

      if (error) throw error;
      if (!data || !data.length) {
        return res.json({ reply: "No CL record found." });
      }

      return res.json({
        reply: "CL bio data:",
        columns: Object.keys(data[0]),
        data
      });
    }

    // CL LIST
    if (intent.type === "CL_LIST") {
      let q = supabase.from("cl_biodata").select("*");
      if (intent.division) q = q.eq("division", intent.division);

      const { data, error } = await q.limit(10);
      if (error) throw error;

      return res.json({
        reply: "CL bio data list:",
        columns: data.length ? Object.keys(data[0]) : [],
        data
      });
    }

    // FALLBACK
    return res.json({
      reply: "I can help with PRs, Estimates, Daily progress, and CL data."
    });

  } catch (err) {
    console.error("AI QUERY ERROR:", err);

    return res.status(500).json({
      reply: "Unable to process request.",
      error: err.message
    });
  }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});


































































