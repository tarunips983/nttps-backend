const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const fsp = require("fs").promises;
const path = require("path");
const mime = require("mime-types");
const pdf = require("pdf-parse");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
const PORT = 3000;

// ✅ CORS
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

// ✅ File paths
const USERS_FILE = path.join(__dirname, "users.json");
const uploadsFolder = path.join(__dirname, "uploads");
const dataFile = path.join(__dirname, "data.json");
const dailyFile = path.join(__dirname, "daily.json");

if (!fs.existsSync(uploadsFolder)) fs.mkdirSync(uploadsFolder);

// ✅ Email Setup
const EMAIL_USER = "tmcamotp@gmail.com";
const EMAIL_PASS = "myve tejj ucgt ikbo";

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

// ✅ Authentication Middleware
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

// ✅ Multer setups
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsFolder),
    filename: (req, file, cb) =>
        cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });
const uploadInMemory = multer({ storage: multer.memoryStorage() });

// ✅ Middleware
app.use("/uploads", express.static(uploadsFolder));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ✅ Read JSON helper
async function readJsonFile(filePath, defaultData = []) {
    try {
        const data = await fsp.readFile(filePath, "utf8");
        if (data.trim() === "") return defaultData;
        return JSON.parse(data);
    } catch (err) {
        return defaultData;
    }
}

// ✅ Safe write JSON
async function safeWriteJson(filePath, data) {
    const tmp = filePath + ".tmp";
    await fsp.writeFile(tmp, JSON.stringify(data, null, 2));
    await fsp.rename(tmp, filePath);
}

// =================================================================
// ✅ RECORD ROUTES
// =================================================================

app.get("/records", async (req, res) => {
    const records = await readJsonFile(dataFile, []);
    res.json(records.filter(r => !r.isDeleted));
});

app.get("/records/trash", authenticateToken, async (req, res) => {
    const records = await readJsonFile(dataFile, []);
    res.json(records.filter(r => r.isDeleted));
});

app.post("/upload", authenticateToken, upload.array("pdfs", 10), async (req, res) => {
    let records = await readJsonFile(dataFile, []);

    if (req.files && req.files.length > 0) {
        req.files.forEach((file) => {
            records.push({
                id: Date.now() + Math.floor(Math.random() * 1000),
                workName: req.body.workName || file.originalname,
                prNo: req.body.prNo || "N/A",
                subDivision: req.body.subDivision || "N/A",
                recordType: req.body.recordType || "Other Record",
                amount: req.body.amount || "0",
                sendTo: req.body.sendTo || "N/A",
                pdfPath: `/uploads/${file.filename}`,
                isDeleted: false,
            });
        });
    }

    await safeWriteJson(dataFile, records);
    res.json({ success: true, records });
});

// ✅ Delete (move to trash)
app.delete("/records/:id", authenticateToken, async (req, res) => {
    let records = await readJsonFile(dataFile, []);
    const id = Number(req.params.id);

    const idx = records.findIndex(r => r.id === id);
    if (idx === -1) return res.status(404).json({ error: "Not found" });

    records[idx].isDeleted = true;
    await safeWriteJson(dataFile, records);

    res.json({ success: true });
});

// ✅ Restore
app.post("/records/:id/restore", authenticateToken, async (req, res) => {
    let records = await readJsonFile(dataFile, []);
    const id = Number(req.params.id);

    const idx = records.findIndex(r => r.id === id);
    if (idx === -1) return res.status(404).json({ error: "Not found" });

    records[idx].isDeleted = false;
    delete records[idx].deletedOn;

    await safeWriteJson(dataFile, records);
    res.json({ success: true });
});

// ✅ Permanent delete from trash
app.delete("/records/trash/:id", authenticateToken, async (req, res) => {
    let records = await readJsonFile(dataFile, []);
    const id = Number(req.params.id);

    const record = records.find(r => r.id === id);
    if (!record) return res.status(404).json({ error: "Not found" });

    if (record.pdfPath) {
        const pdfPath = path.join(__dirname, record.pdfPath);
        if (fs.existsSync(pdfPath)) await fsp.unlink(pdfPath);
    }

    records = records.filter(r => r.id !== id);
    await safeWriteJson(dataFile, records);

    res.json({ success: true });
});

// =================================================================
// ✅ PDF EXTRACTION ROUTE (WORKING, NO AI)
// =================================================================

app.post("/extract-pdf", authenticateToken, uploadInMemory.single("pdfFile"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No PDF file" });

    try {
        const data = await pdf(req.file.buffer);
        const text = data.text;

        const prNoMatch = text.match(/PR\s*No\.?\s*[:\-]?\s*(\d+)/i);
        const amountMatch = text.match(/Estimated\s*Value\s*[:\-]?\s*([\d,]+\.?\d*)/i);
        const divisionMatch = text.match(/Division\s*:\s*([A-Za-z0-9\-]+)/i);
        const briefMatch = text.match(/Brief Description\s*:\s*(.+)/i);

        res.json({
            prNo: prNoMatch ? prNoMatch[1].trim() : "",
            workName: briefMatch ? briefMatch[1].trim() : "",
            amount: amountMatch ? amountMatch[1].replace(/,/g, "") : "",
            subDivision: divisionMatch ? divisionMatch[1] : "",
            recordType: "PR"
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to read PDF content" });
    }
});

// =================================================================
// ✅ DAILY PROGRESS ROUTES
// =================================================================

app.get("/daily-progress", async (req, res) => {
    const snapshots = await readJsonFile(dailyFile, []);
    res.json(snapshots);
});

app.post("/daily-progress", authenticateToken, async (req, res) => {
    const { id, date, tableHTML, rowCount } = req.body;
    let snapshots = await readJsonFile(dailyFile, []);

    if (!date || tableHTML === undefined)
        return res.status(400).json({ error: "Missing fields" });

    if (id) {
        const index = snapshots.findIndex(s => s.id == id);
        if (index !== -1) {
            snapshots[index] = { ...snapshots[index], date, tableHTML, rowCount };
        }
    } else {
        snapshots.push({
            id: Date.now(),
            date,
            tableHTML,
            rowCount
        });
    }

    await safeWriteJson(dailyFile, snapshots);
    res.json({ success: true });
});

// =================================================================
// ✅ USER AUTH (Register, OTP, Login)
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
        res.status(500).json({ message: "Server error" });
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

    if (!user || !await bcrypt.compare(password, user.passwordHash))
        return res.status(401).json({ message: "Invalid login" });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "Login success", token });
});

// =================================================================
// ✅ STATIC FILE SERVING
// =================================================================

app.use(express.static(__dirname, { extensions: ["html"] }));

// =================================================================
// ✅ START SERVER
// =================================================================

app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ Server running at http://172.21.16.51:${PORT}`);
});
