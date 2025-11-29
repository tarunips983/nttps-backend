require("dotenv").config(); // Load .env first

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

// =========================
// SUPABASE
// =========================
const { createClient } = require("@supabase/supabase-js");

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

// ---------------------------------------------
// EMAIL SETUP
// ---------------------------------------------
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

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
function mapRecordRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workName: row.work_name,
    prNo: row.pr_no,
    subDivision: row.sub_division,
    recordType: row.record_type,
    amount: row.amount,
    sendTo: row.send_to,
    pdfPath: row.pdf_url,
    isDeleted: row.is_deleted,
    createdAt: row.created_at,
  };
}

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
const PDF_BUCKET = "pdfs"; // make sure this bucket exists in Supabase

app.post(
  "/upload",
  authenticateToken,
  uploadInMemory.array("pdfs", 10),
  async (req, res) => {
    try {
      const {
        id, // optional for edit
        workName,
        prNo,
        subDivision,
        recordType,
        amount,
        sendTo,
        pdfPath, // old path (if editing without new file)
      } = req.body;

      let newPdfUrl = null;

      // If a file is uploaded, store it in Supabase
      if (req.files && req.files.length > 0) {
        const file = req.files[0]; // you currently use only one PDF per record

        const ext =
          path.extname(file.originalname) ||
          (file.mimetype === "application/pdf" ? ".pdf" : "");
        const uniqueName =
          Date.now() +
          "_" +
          Math.random().toString(36).slice(2) +
          ext.replace(/[^a-zA-Z0-9.]/g, "_");

        const { data: uploadData, error: uploadError } = await supabase
          .storage
          .from(PDF_BUCKET)
          .upload(uniqueName, file.buffer, {
            contentType: file.mimetype || "application/pdf",
            upsert: false,
          });

        if (uploadError) {
          console.error("Supabase upload error:", uploadError);
          return res.status(500).json({ error: "Failed to upload PDF" });
        }

        const { data: publicUrlData } = supabase
          .storage
          .from(PDF_BUCKET)
          .getPublicUrl(uploadData.path);

        newPdfUrl = publicUrlData.publicUrl;
      }

      // If editing but no new file, keep old pdfPath
      const finalPdfUrl = newPdfUrl || pdfPath || null;

      if (!id && !finalPdfUrl) {
        return res.status(400).json({ error: "PDF file is required for new records" });
      }

      if (id) {
        // UPDATE existing record
        const updatePayload = {
          work_name: workName || null,
          pr_no: prNo || null,
          sub_division: subDivision || null,
          record_type: recordType || null,
          amount: amount || null,
          send_to: sendTo || null,
        };
        if (finalPdfUrl) {
          updatePayload.pdf_url = finalPdfUrl;
        }

        const { data, error } = await supabase
          .from("records")
          .update(updatePayload)
          .eq("id", Number(id))
          .select("*");

        if (error) throw error;

        return res.json({
          success: true,
          record: mapRecordRow(data[0]),
        });
      } else {
        // INSERT new record
        const { data, error } = await supabase
          .from("records")
          .insert({
            work_name: workName || null,
            pr_no: prNo || null,
            sub_division: subDivision || null,
            record_type: recordType || "Other Record",
            amount: amount || 0,
            send_to: sendTo || null,
            pdf_url: finalPdfUrl,
            is_deleted: false,
          })
          .select("*");

        if (error) throw error;

        return res.json({
          success: true,
          record: mapRecordRow(data[0]),
        });
      }
    } catch (err) {
      console.error("UPLOAD ERROR:", err);
      res.status(500).json({ error: "Upload failed" });
    }
  }
);

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
const pdfjsLib = require("pdfjs-dist");

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

const CL_BUCKET = "cl-photo_urls";

// SAVE / UPDATE CL
app.post("/cl", authenticateToken, uploadInMemory.single("photo_url"), async (req, res) => {
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
      photo_urlUrl // existing photo_url path
    } = req.body;

    let newphoto_urlUrl = null;

    // Upload new photo_url only if file exists
    if (req.file) {
      const ext = path.extname(req.file.originalname) || ".jpg";

      const uniqueName =
        Date.now() + "_" + Math.random().toString(36).slice(2) + ext;

      const { data: uploadData, error: uploadErr } = await supabase.storage
        .from(CL_BUCKET)
        .upload(uniqueName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false,
        });

      if (uploadErr) throw uploadErr;

      const { data: urlData } = supabase.storage
        .from(CL_BUCKET)
        .getPublicUrl(uploadData.path);

      newphoto_urlUrl = urlData.publicUrl;
    }

    const finalphoto_url = newphoto_urlUrl || photo_urlUrl || null;

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
      photo_url: finalphoto_url
    };

    let result;

    if (id) {
      // update
      const { data, error } = await supabase
        .from("cl_biodata")
        .update(payload)
        .eq("id", id)
        .select("*");
      if (error) throw error;
      result = data[0];
    } else {
      // insert
      const { data, error } = await supabase.from("cl_biodata").insert(payload).select("*");
      if (error) throw error;
      result = data[0];
    }

    res.json({ success: true, cl: result });

  } catch (err) {
    console.error("CL SAVE ERROR:", err);
    res.status(500).json({ error: "Failed to save CL" });
  }
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


// =================================================================
// START SERVER
// =================================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});











