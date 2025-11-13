require("dotenv").config(); // Load .env first

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const fsp = require("fs").promises;
const path = require("path");
const pdf = require("pdf-parse");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

// CLOUDINARY IMPORTS
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");

// CONFIGURE CLOUDINARY
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();

// ---------------------------------------------
// CORS
// ---------------------------------------------
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

// ---------------------------------------------
// FILE PATHS
// ---------------------------------------------
const USERS_FILE = path.join(__dirname, "users.json");
const uploadsFolder = path.join(__dirname, "uploads"); // old path but unused
const dataFile = path.join(__dirname, "data.json");
const dailyFile = path.join(__dirname, "daily.json");

if (!fs.existsSync(uploadsFolder)) fs.mkdirSync(uploadsFolder);

// ---------------------------------------------
// EMAIL SETUP
// ---------------------------------------------
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// ---------------------------------------------
// AUTHENTICATION MIDDLEWARE
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
// MULTER MEMORY STORAGE FOR CLOUDINARY
// ---------------------------------------------
const uploadInMemory = multer({ storage: multer.memoryStorage() });

// ---------------------------------------------
// MIDDLEWARE
// ---------------------------------------------
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ---------------------------------------------
// UTILS
// ---------------------------------------------
async function readJsonFile(filePath, defaultData = []) {
    try {
        const data = await fsp.readFile(filePath, "utf8");
        if (!data.trim()) return defaultData;
        return JSON.parse(data);
    } catch {
        return defaultData;
    }
}

async function safeWriteJson(filePath, data) {
    const temp = filePath + ".tmp";
    await fsp.writeFile(temp, JSON.stringify(data, null, 2));
    await fsp.rename(temp, filePath);
}

// =================================================================
// RECORD ROUTES
// =================================================================

// Get all non-deleted records
app.get("/records", async (req, res) => {
    const records = await readJsonFile(dataFile, []);
    res.json(records.filter(r => !r.isDeleted));
});

// Get trash
app.get("/records/trash", authenticateToken, async (req, res) => {
    const records = await readJsonFile(dataFile, []);
    res.json(records.filter(r => r.isDeleted));
});

// ---------------------------------------------------------
// CLOUDINARY UPLOAD ROUTE — REPLACES OLD LOCAL UPLOAD
// ---------------------------------------------------------
app.post("/upload", authenticateToken, uploadInMemory.array("pdfs", 10), async (req, res) => {
    try {
        let records = await readJsonFile(dataFile, []);
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: "No PDFs uploaded" });
        }

        const uploadedFiles = await Promise.all(
            req.files.map(file =>
                new Promise((resolve, reject) => {
                    const uploadStream = cloudinary.uploader.upload_stream(
                        {
                            folder: "pdf_uploads",
                            resource_type: "raw"
                        },
                        (error, result) => {
                            if (error) return reject(error);
                            resolve({ result, originalname: file.originalname });
                        }
                    );
                    streamifier.createReadStream(file.buffer).pipe(uploadStream);
                })
            )
        );

        // Save in JSON database
        uploadedFiles.forEach(u => {
            records.push({
                id: Date.now() + Math.floor(Math.random() * 1000),
                workName: req.body.workName || u.originalname,
                prNo: req.body.prNo || "N/A",
                subDivision: req.body.subDivision || "N/A",
                recordType: req.body.recordType || "Other Record",
                amount: req.body.amount || "0",
                sendTo: req.body.sendTo || "N/A",
                pdfPath: u.result.secure_url,
                cloudinaryPublicId: u.result.public_id,
                isDeleted: false
            });
        });

        await safeWriteJson(dataFile, records);
        res.json({ success: true, records });

    } catch (err) {
        console.error("UPLOAD ERROR:", err);
        res.status(500).json({ error: "Upload failed" });
    }
});

// Move to trash
app.delete("/records/:id", authenticateToken, async (req, res) => {
    let records = await readJsonFile(dataFile, []);
    const id = Number(req.params.id);

    const index = records.findIndex(r => r.id === id);
    if (index === -1) return res.status(404).json({ error: "Not found" });

    records[index].isDeleted = true;
    await safeWriteJson(dataFile, records);

    res.json({ success: true });
});

// Restore
app.post("/records/:id/restore", authenticateToken, async (req, res) => {
    let records = await readJsonFile(dataFile, []);
    const id = Number(req.params.id);

    const index = records.findIndex(r => r.id === id);
    if (index === -1) return res.status(404).json({ error: "Not found" });

    records[index].isDeleted = false;
    await safeWriteJson(dataFile, records);

    res.json({ success: true });
});

// Permanent Delete (Cloudinary Delete)
app.delete("/records/trash/:id", authenticateToken, async (req, res) => {
    let records = await readJsonFile(dataFile, []);
    const id = Number(req.params.id);

    const record = records.find(r => r.id === id);
    if (!record) return res.status(404).json({ error: "Not found" });

    if (record.cloudinaryPublicId) {
        try {
            await cloudinary.uploader.destroy(record.cloudinaryPublicId, {
                resource_type: "raw"
            });
        } catch (err) {
            console.log("Cloudinary delete error:", err);
        }
    }

    records = records.filter(r => r.id !== id);
    await safeWriteJson(dataFile, records);

    res.json({ success: true });
});

// =================================================================
// PDF EXTRACTION
// =================================================================

app.post("/extract-pdf", authenticateToken, uploadInMemory.single("pdfFile"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No PDF uploaded" });

    try {
        const data = await pdf(req.file.buffer);
        const text = data.text;

        res.json({
            prNo: (text.match(/PR\s*No\.?\s*[:\-]?\s*(\d+)/i) || ["", ""])[1],
            workName: (text.match(/Brief Description\s*:\s*(.+)/i) || ["", ""])[1],
            amount: (text.match(/Estimated\s*Value\s*[:\-]?\s*([\d,]+\.?\d*)/i) || ["", ""])[1],
            subDivision: (text.match(/Division\s*:\s*([A-Za-z0-9\-]+)/i) || ["", ""])[1],
            recordType: "PR"
        });

    } catch (err) {
        res.status(500).json({ error: "Failed to read PDF" });
    }
});

// =================================================================
// DAILY PROGRESS ROUTES
// =================================================================

app.get("/daily-progress", async (req, res) => {
    res.json(await readJsonFile(dailyFile, []));
});

app.get("/daily-progress/:id", async (req, res) => {
    const id = Number(req.params.id);
    const snaps = await readJsonFile(dailyFile, []);
    const snap = snaps.find(s => s.id === id);
    if (!snap) return res.status(404).json({ error: "Not found" });
    res.json(snap);
});

app.post("/daily-progress", authenticateToken, async (req, res) => {
    const { id, date, tableHTML, rowCount } = req.body;

    let snaps = await readJsonFile(dailyFile, []);

    if (id) {
        const index = snaps.findIndex(s => s.id == id);
        if (index !== -1) {
            snaps[index] = { ...snaps[index], date, tableHTML, rowCount };
        }
    } else {
        snaps.push({ id: Date.now(), date, tableHTML, rowCount });
    }

    await safeWriteJson(dailyFile, snaps);
    res.json({ success: true });
});

app.delete("/daily-progress/:id", authenticateToken, async (req, res) => {
    let snaps = await readJsonFile(dailyFile, []);
    const id = Number(req.params.id);

    snaps = snaps.filter(s => s.id !== id);
    await safeWriteJson(dailyFile, snaps);

    res.json({ success: true });
});

// =================================================================
// USER AUTH
// =================================================================

let pendingVerifications = {};

app.post("/register-send-otp", async (req, res) => {
    try {
        const { email, password, inviteCode } = req.body;

        if (!email || !password || inviteCode !== "810632")
            return res.status(400).json({ message: "Invalid data" });

        const users = await readJsonFile(USERS_FILE, []);
        if (users.find(u => u.username === email))
            return res.status(409).json({ message: "Already registered" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const passwordHash = await bcrypt.hash(password, 10);

        pendingVerifications[email] = {
            email,
            passwordHash,
            otp,
            expires: Date.now() + 10 * 60 * 1000
        };

        await transporter.sendMail({
            from: EMAIL_USER,
            to: email,
            subject: "Verification Code",
            text: `Your OTP is ${otp}`
        });

        res.json({ message: "OTP sent" });

    } catch (err) {
        res.status(500).json({ message: "Email sending failed", error: err.toString() });
    }
});

app.post("/register-verify", async (req, res) => {
    const { email, otp } = req.body;

    const pending = pendingVerifications[email];
    if (!pending || pending.otp !== otp)
        return res.status(400).json({ message: "Invalid OTP" });

    const users = await readJsonFile(USERS_FILE, []);
    users.push({ username: email, passwordHash: pending.passwordHash });

    await safeWriteJson(USERS_FILE, users);
    delete pendingVerifications[email];

    res.json({ message: "Registration complete" });
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const users = await readJsonFile(USERS_FILE, []);
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
        return res.status(401).json({ message: "Invalid login" });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "Login success", token });
});

// =================================================================
// STATIC FILES
// =================================================================
app.use(express.static(__dirname, { extensions: ["html"] }));

// =================================================================
// START SERVER
// =================================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
