import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import dns from "node:dns";
import { MongoClient, ObjectId } from "mongodb";
import { Resend } from "resend";
import Stripe from "stripe";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
    randomInt,
    randomBytes,
    createHmac,
    createHash,
    timingSafeEqual
} from "node:crypto";

dotenv.config();

dns.setServers(["8.8.8.8", "1.1.1.1"]);

const app = express();

// Hide Express technology information from HTTP responses
app.disable("x-powered-by");

const port = process.env.PORT || 5000;

const requiredEnv = [
    "DB_USER",
    "DB_PASS",
    "RESEND_API_KEY",
    "EMAIL_FROM",
    "OTP_SECRET",
    "JWT_SECRET",
    "ADMIN_SETUP_SECRET"
];

for (const key of requiredEnv) {
    if (!process.env[key]) {
        throw new Error(`Missing environment variable: ${key}`);
    }
}

if (
    process.env.JWT_SECRET.length < 32 ||
    process.env.ADMIN_SETUP_SECRET.length < 32
) {
    throw new Error("JWT_SECRET and ADMIN_SETUP_SECRET must be at least 32 characters.");
}


// ==========================================
// CONFIGURATION
// ==========================================

const FRONTEND_URL = (
    process.env.FRONTEND_URL || "http://localhost:5173"
).replace(/\/$/, "");

const allowedOrigins = [
    FRONTEND_URL,
    "http://localhost:5173",
    "http://127.0.0.1:5173"
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests without an Origin header (e.g. server-to-server).
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
        "Content-Type",
        "Authorization",
        "x-admin-setup-secret",
        "stripe-signature"
    ]
}));

app.use(express.json({
    limit: "20kb",
    verify: (req, res, buffer) => {
        if (req.originalUrl === "/api/stripe/webhook") {
            req.rawBody = Buffer.from(buffer);
        }
    }
}));


const resend = new Resend(process.env.RESEND_API_KEY);

const stripe = process.env.STRIPE_SECRET_KEY
    ? new Stripe(process.env.STRIPE_SECRET_KEY)
    : null;

const membershipPlans = {
    basic: {
        name: "Basic",
        amount: 1500,
        currency: "usd",
        durationMonths: 1
    },
    premium: {
        name: "Premium",
        amount: 3000,
        currency: "usd",
        durationMonths: 3
    },
    vip: {
        name: "VIP",
        amount: 6000,
        currency: "usd",
        durationMonths: 6
    }
};

// ==========================================
// MONGODB
// ==========================================

const client = new MongoClient(
    `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@xpointcluster.j3qynmm.mongodb.net/`
);

let db;

const connectDB = async () => {
    await client.connect();

    db = client.db("da_web_social_club");

    await db.command({ ping: 1 });

    console.log("Successfully connected to MongoDB!");

    await initializeDatabase();
};


const initializeDatabase = async () => {

    // ==========================================
    // MEMBERS COLLECTION
    // ==========================================

    await db.collection("members").createIndexes([
        {
            key: { memberId: 1 },
            name: "unique_member_id",
            unique: true
        },
        {
            key: { accessTokenHash: 1 },
            name: "unique_access_token_hash",
            unique: true
        },
        {
            key: { email: 1 },
            name: "unique_member_email",
            unique: true
        },
        {
            key: { membershipType: 1 },
            name: "membership_type_index"
        },
        {
            key: { status: 1 },
            name: "member_status_index"
        },
        {
            key: { expiryDate: 1 },
            name: "membership_expiry_index"
        },
        {
            key: { createdAt: -1 },
            name: "member_created_at_index"
        },
        {
            key: { cardAccessTokenHashes: 1 },
            name: "card_access_token_hashes_index"
        }
    ]);

    // ==========================================
    // PURCHASES COLLECTION
    // ==========================================

    await db.collection("purchases").createIndexes([
        {
            key: { memberId: 1, purchasedAt: -1 },
            name: "member_purchase_history"
        },
        {
            key: { paymentStatus: 1 },
            name: "payment_status_index"
        },
        {
            key: { purchasedAt: -1 },
            name: "recent_purchases_index"
        },
        {
            key: { stripeSessionId: 1 },
            name: "unique_stripe_session_id",
            unique: true,
            partialFilterExpression: {
                stripeSessionId: { $type: "string" }
            }
        },
        {
            key: { stripePaymentIntentId: 1 },
            name: "unique_stripe_payment_intent",
            unique: true,
            partialFilterExpression: {
                stripePaymentIntentId: { $type: "string" }
            }
        }
    ]);

    // ==========================================
    // ADMINS COLLECTION
    // ==========================================

    await db.collection("admins").createIndexes([
        {
            key: { email: 1 },
            name: "unique_admin_email",
            unique: true
        }
    ]);

    // ==========================================
    // OTP COLLECTION
    // ==========================================

    await db.collection("otps").createIndexes([
        {
            key: { email: 1, createdAt: -1 },
            name: "otp_email_created_at"
        },
        {
            key: { expiresAt: 1 },
            name: "otp_expiration_ttl",
            expireAfterSeconds: 0
        }
    ]);

    // ==========================================
    // ADMIN SETUP COLLECTION
    // ==========================================

    const setupCollection = await db.listCollections(
        { name: "admin_setup" },
        { nameOnly: true }
    ).toArray();

    if (setupCollection.length === 0) {
        await db.createCollection("admin_setup");
    }

    console.log("Database collections and indexes initialized!");
};


// ==========================================
// HELPER FUNCTIONS
// ==========================================

const hashOTP = (email, otp) => {
    return createHmac("sha256", process.env.OTP_SECRET)
        .update(`${email}:${otp}`)
        .digest("hex");
};

const hashToken = (token) => {
    return createHash("sha256")
        .update(token)
        .digest("hex");
};

const compareHashes = (a, b) => {
    const bufferA = Buffer.from(a, "hex");
    const bufferB = Buffer.from(b, "hex");

    return (
        bufferA.length === bufferB.length &&
        timingSafeEqual(bufferA, bufferB)
    );
};

const compareSecrets = (a, b) => {
    const hashA = createHash("sha256").update(a).digest();
    const hashB = createHash("sha256").update(b).digest();

    return timingSafeEqual(hashA, hashB);
};

const addCalendarMonths = (date, months) => {
    const result = new Date(date);
    const originalDay = result.getDate();

    result.setDate(1);
    result.setMonth(result.getMonth() + months);

    const lastDay = new Date(
        result.getFullYear(),
        result.getMonth() + 1,
        0
    ).getDate();

    result.setDate(Math.min(originalDay, lastDay));

    return result;
};

const generateMemberId = () => {
    const year = new Date().getFullYear();
    const randomPart = randomBytes(3).toString("hex").toUpperCase();

    return `DA-${year}-${randomPart}`;
};

const isValidEmail = (email) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};


// ==========================================
// RATE LIMITER
// ==========================================

const createRateLimiter = (maxRequests, windowMs) => {
    const requests = new Map();

    return (req, res, next) => {
        const ip = req.ip || req.socket.remoteAddress || "unknown";
        const now = Date.now();

        let record = requests.get(ip);

        if (!record || now - record.startTime >= windowMs) {
            record = {
                count: 0,
                startTime: now
            };
        }

        record.count += 1;
        requests.set(ip, record);

        if (record.count > maxRequests) {
            const retryAfter = Math.ceil(
                (windowMs - (now - record.startTime)) / 1000
            );

            res.set("Retry-After", String(retryAfter));

            return res.status(429).json({
                success: false,
                message: "Too many requests. Please try again later."
            });
        }

        next();
    };
};

// Rate limiters for sensitive routes
const adminSetupLimiter = createRateLimiter(
    3,
    60 * 60 * 1000
);

const adminLoginLimiter = createRateLimiter(
    10,
    15 * 60 * 1000
);

const sendOTPLimiter = createRateLimiter(
    5,
    15 * 60 * 1000
);

const verifyOTPLimiter = createRateLimiter(
    10,
    15 * 60 * 1000
);

const checkoutLimiter = createRateLimiter(
    10,
    15 * 60 * 1000
);

const renewalLimiter = createRateLimiter(
    10,
    15 * 60 * 1000
);

const registrationLimiter = createRateLimiter(
    10,
    15 * 60 * 1000
);


// ==========================================
// ADMIN AUTHENTICATION MIDDLEWARE
// ==========================================

const verifyAdmin = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Admin authentication required."
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (
            decoded.role !== "admin" ||
            !ObjectId.isValid(decoded.sub)
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid admin authentication."
            });
        }

        const admin = await db.collection("admins").findOne({
            _id: new ObjectId(decoded.sub),
            status: "active"
        });

        if (!admin) {
            return res.status(401).json({
                success: false,
                message: "Admin account not found or disabled."
            });
        }

        req.admin = {
            id: admin._id.toString(),
            name: admin.name,
            email: admin.email,
            role: admin.role
        };

        next();

    } catch (error) {
        if (
            error.name === "JsonWebTokenError" ||
            error.name === "TokenExpiredError"
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid or expired admin token."
            });
        }

        console.error("Admin authentication error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to authenticate admin."
        });
    }
};

// ==========================================
// TEST ROUTE
// ==========================================

app.get("/", (req, res) => {
    res.send("DA WEB SOCIAL CLUB server is running");
});

// ==========================================
// ADMIN: ONE-TIME INITIAL SETUP
// ==========================================

app.post("/api/admin/setup", adminSetupLimiter, async (req, res) => {
    const session = client.startSession();

    try {
        const setupSecret = req.headers["x-admin-setup-secret"];

        if (
            typeof setupSecret !== "string" ||
            !compareSecrets(
                setupSecret,
                process.env.ADMIN_SETUP_SECRET
            )
        ) {
            return res.status(403).json({
                success: false,
                message: "Invalid admin setup authorization."
            });
        }

        const { name, email, password } = req.body;

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            !name.trim() ||
            !isValidEmail(email.trim().toLowerCase()) ||
            password.length < 12 ||
            password.length > 128
        ) {
            return res.status(400).json({
                success: false,
                message: "Provide a valid name, email, and password of at least 12 characters."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const passwordHash = await bcrypt.hash(password, 12);

        let createdAdmin = null;


        await session.withTransaction(async () => {
            // Create a unique database-level lock for initial admin setup.
            // MongoDB automatically enforces uniqueness on the _id field.
            await db.collection("admin_setup").insertOne(
                {
                    _id: "initial-admin",
                    createdAt: new Date()
                },
                { session }
            );

            const admins = db.collection("admins");

            const existingAdmin = await admins.findOne(
                {},
                { session }
            );


            if (existingAdmin) {
                const error = new Error(
                    "Admin setup has already been completed."
                );
                error.statusCode = 409;
                throw error;
            }

            const now = new Date();

            const admin = {
                name: name.trim(),
                email: normalizedEmail,
                passwordHash,
                role: "admin",
                status: "active",
                createdAt: now,
                updatedAt: now
            };

            const result = await admins.insertOne(
                admin,
                { session }
            );

            createdAdmin = {
                id: result.insertedId.toString(),
                name: admin.name,
                email: admin.email,
                role: admin.role
            };
        });

        return res.status(201).json({
            success: true,
            message: "Initial admin account created successfully. You can now log in.",
            admin: createdAdmin
        });

    } catch (error) {
        console.error("Admin setup error:", error);

        if (
            error.code === 11000 ||
            error.code === 112 ||
            error.code === 251
        ) {
            return res.status(409).json({
                success: false,
                message: "Admin setup could not be completed. An admin may already exist; please try logging in."
            });
        }

        return res.status(error.statusCode || 500).json({
            success: false,
            message: error.statusCode
                ? error.message
                : "Unable to create admin account."
        });

    } finally {
        await session.endSession();
    }
});

// ==========================================
// ADMIN: LOGIN
// ==========================================

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !isValidEmail(email.trim().toLowerCase())
        ) {
            return res.status(400).json({
                success: false,
                message: "Please provide valid login credentials."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const admin = await db.collection("admins").findOne({
            email: normalizedEmail
        });

        if (!admin || admin.status !== "active") {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const passwordMatches = await bcrypt.compare(
            password,
            admin.passwordHash
        );

        if (!passwordMatches) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const token = jwt.sign(
            {
                role: "admin"
            },
            process.env.JWT_SECRET,
            {
                subject: admin._id.toString(),
                expiresIn: "8h"
            }
        );

        await db.collection("admins").updateOne(
            { _id: admin._id },
            {
                $set: {
                    lastLoginAt: new Date(),
                    updatedAt: new Date()
                }
            }
        );

        return res.json({
            success: true,
            message: "Admin login successful.",
            token,
            admin: {
                id: admin._id.toString(),
                name: admin.name,
                email: admin.email,
                role: admin.role
            }
        });

    } catch (error) {
        console.error("Admin login error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to log in."
        });
    }
});

// ==========================================
// ADMIN: GET CURRENT ADMIN
// ==========================================

app.get("/api/admin/me", verifyAdmin, async (req, res) => {
    return res.json({
        success: true,
        admin: req.admin
    });
});

// ==========================================
// CUSTOMER REGISTRATION
// ==========================================

app.post("/api/members/register", registrationLimiter, async (req, res) => {
    try {
        const {
            fullName,
            email,
            phone,
            dateOfBirth,
            membership,
            terms
        } = req.body;


        if (
            typeof fullName !== "string" ||
            typeof email !== "string" ||
            typeof phone !== "string" ||
            typeof dateOfBirth !== "string" ||
            typeof membership !== "string" ||
            terms !== true ||
            !fullName.trim() ||
            !email.trim() ||
            !phone.trim() ||
            !dateOfBirth.trim() ||
            !membership.trim()
        ) {
            return res.status(400).json({
                success: false,
                message: "Please complete all required fields correctly."
            });
        }

        if (
            fullName.trim().length > 100 ||
            email.trim().length > 254 ||
            phone.trim().length > 30
        ) {
            return res.status(400).json({
                success: false,
                message: "One or more fields exceed the allowed length."
            });
        }


        const normalizedEmail = email.trim().toLowerCase();
        const normalizedPlan = membership.trim().toLowerCase();

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({
                success: false,
                message: "Please provide a valid email address."
            });
        }

        if (!membershipPlans[normalizedPlan]) {
            return res.status(400).json({
                success: false,
                message: "Invalid membership plan."
            });
        }

        const dob = /^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth)
            ? new Date(`${dateOfBirth}T00:00:00.000Z`)
            : null;

        if (
            !dob ||
            Number.isNaN(dob.getTime()) ||
            dob.toISOString().slice(0, 10) !== dateOfBirth ||
            dob > new Date()
        ) {
            return res.status(400).json({
                success: false,
                message: "Please provide a valid date of birth."
            });
        }

        const existingMember = await db.collection("members").findOne({
            email: normalizedEmail
        });

        if (existingMember) {
            return res.status(409).json({
                success: false,
                code: "EXISTING_MEMBER",
                message: "An account with this email already exists. Please verify your email to continue."
            });
        }

        const plan = membershipPlans[normalizedPlan];
        const now = new Date();

        const purchase = {
            memberId: null,

            customer: {
                fullName: fullName.trim(),
                email: normalizedEmail,
                phone: phone.trim(),
                dateOfBirth: dob
            },

            plan: normalizedPlan,
            amount: plan.amount,
            currency: plan.currency,
            durationMonths: plan.durationMonths,

            paymentStatus: "pending",
            paymentGateway: "stripe",

            stripeSessionId: null,
            stripePaymentIntentId: null,

            purchasedAt: now,
            membershipStartDate: null,
            membershipExpiryDate: null,

            createdAt: now,
            updatedAt: now
        };

        const result = await db.collection("purchases").insertOne(purchase);

        return res.status(201).json({
            success: true,
            message: "Registration information saved successfully.",
            purchaseId: result.insertedId,
            plan: plan.name,
            amount: plan.amount,
            currency: plan.currency,
            durationMonths: plan.durationMonths
        });

    } catch (error) {
        console.error("Registration error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to complete registration."
        });
    }
});

// ==========================================
// SEND OTP
// ==========================================

app.post("/api/members/send-otp", sendOTPLimiter, async (req, res) => {
    try {
        const email = typeof req.body.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";

        if (!email || !isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: "Please provide a valid email address."
            });
        }

        const member = await db.collection("members").findOne({
            email
        });

        if (!member) {
            return res.json({
                success: true,
                message: "If an account exists, an OTP will be sent."
            });
        }

        const otps = db.collection("otps");
        const now = new Date();

        const recentOTP = await otps.findOne({
            email,
            createdAt: {
                $gt: new Date(now.getTime() - 60 * 1000)
            }
        });

        if (recentOTP) {
            return res.status(429).json({
                success: false,
                message: "Please wait before requesting another OTP."
            });
        }

        const otp = randomInt(100000, 1000000).toString();

        await otps.deleteMany({ email });

        await otps.insertOne({
            email,
            otpHash: hashOTP(email, otp),
            verified: false,
            attempts: 0,
            createdAt: now,
            expiresAt: new Date(now.getTime() + 5 * 60 * 1000)
        });

        const emailResult = await resend.emails.send({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: "Your DA WEB SOCIAL CLUB verification code",
            html: `
                <div style="background:#080808;padding:35px;color:#ffffff;font-family:Arial,sans-serif;text-align:center;">
                    <h1 style="color:#d4af37;">DA WEB SOCIAL CLUB</h1>
                    <p>Your email verification code is:</p>
                    <h2 style="letter-spacing:8px;color:#d4af37;">${otp}</h2>
                    <p>This code expires in 5 minutes.</p>
                    <p style="color:#999;">If you did not request this code, you can ignore this email.</p>
                </div>
            `
        });

        if (emailResult.error) {
            await otps.deleteMany({ email });

            console.error("Resend error:", emailResult.error);

            return res.status(500).json({
                success: false,
                message: "Unable to send verification email."
            });
        }

        return res.json({
            success: true,
            message: "If an account exists, an OTP will be sent."
        });

    } catch (error) {
        console.error("Send OTP error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to send OTP."
        });
    }
});

// ==========================================
// VERIFY OTP
// ==========================================

app.post("/api/members/verify-otp", verifyOTPLimiter, async (req, res) => {
    try {
        const email = typeof req.body.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";

        const otp = typeof req.body.otp === "string"
            ? req.body.otp.trim()
            : "";

        if (
            !email ||
            !isValidEmail(email) ||
            !/^\d{6}$/.test(otp)
        ) {
            return res.status(400).json({
                success: false,
                message: "Please provide a valid email and six-digit OTP."
            });
        }

        const otps = db.collection("otps");

        const otpRecord = await otps.findOne({
            email,
            verified: false
        });

        if (!otpRecord) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired OTP."
            });
        }

        if (otpRecord.expiresAt <= new Date()) {
            await otps.deleteOne({ _id: otpRecord._id });

            return res.status(400).json({
                success: false,
                message: "OTP has expired. Please request a new one."
            });
        }

        if (otpRecord.attempts >= 5) {
            await otps.deleteOne({ _id: otpRecord._id });

            return res.status(429).json({
                success: false,
                message: "Too many incorrect attempts. Request a new OTP."
            });
        }


        const attemptResult = await otps.updateOne(
            {
                _id: otpRecord._id,
                verified: false,
                attempts: { $lt: 5 },
                expiresAt: { $gt: new Date() }
            },
            {
                $inc: { attempts: 1 }
            }
        );

        if (attemptResult.modifiedCount !== 1) {
            await otps.deleteOne({
                _id: otpRecord._id,
                verified: false
            });

            return res.status(429).json({
                success: false,
                message: "Too many incorrect attempts. Request a new OTP."
            });
        }


        const submittedHash = hashOTP(email, otp);

        if (!compareHashes(submittedHash, otpRecord.otpHash)) {
            return res.status(400).json({
                success: false,
                message: "Incorrect OTP."
            });
        }

        const verificationToken = randomBytes(32).toString("hex");
        const tokenExpiry = new Date(Date.now() + 10 * 60 * 1000);

        const verificationUpdate = await otps.updateOne(
            {
                _id: otpRecord._id,
                verified: false,
                attempts: { $lte: 5 },
                expiresAt: { $gt: new Date() }
            },
            {
                $set: {
                    verified: true,
                    verifiedAt: new Date(),
                    verificationTokenHash: hashToken(verificationToken),
                    expiresAt: tokenExpiry
                }
            }
        );

        if (verificationUpdate.modifiedCount !== 1) {
            return res.status(400).json({
                success: false,
                message: "OTP has already been used or expired. Please request a new one."
            });
        }

        return res.json({
            success: true,
            message: "Email verified successfully.",
            verificationToken,
            expiresAt: tokenExpiry
        });

    } catch (error) {
        console.error("Verify OTP error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to verify OTP."
        });
    }
});

// ==========================================
// CREATE RENEWAL PURCHASE
// ==========================================

app.post("/api/members/renewal-purchase", renewalLimiter, async (req, res) => {
    const { verificationToken, membership } = req.body;

    if (
        typeof verificationToken !== "string" ||
        !/^[a-f0-9]{64}$/i.test(verificationToken)
    ) {
        return res.status(400).json({
            success: false,
            message: "A valid email verification token is required."
        });
    }

    const normalizedPlan = String(membership || "").trim().toLowerCase();
    const plan = membershipPlans[normalizedPlan];

    if (!plan) {
        return res.status(400).json({
            success: false,
            message: "Please select a valid membership plan."
        });
    }

    const session = client.startSession();

    try {
        let renewalPurchase = null;

        await session.withTransaction(async () => {
            const now = new Date();
            const tokenHash = hashToken(verificationToken);
            const otps = db.collection("otps");
            const members = db.collection("members");
            const purchases = db.collection("purchases");

            const otpRecord = await otps.findOne(
                {
                    verificationTokenHash: tokenHash,
                    verified: true,
                    consumedAt: { $exists: false },
                    expiresAt: { $gt: now }
                },
                { session }
            );

            if (!otpRecord) {
                const error = new Error(
                    "Verification token is invalid, expired, or already used. Please verify your email again."
                );
                error.statusCode = 401;
                throw error;
            }

            const member = await members.findOne(
                { email: otpRecord.email },
                { session }
            );

            if (!member) {
                const error = new Error(
                    "No existing membership was found for this verified email."
                );
                error.statusCode = 404;
                throw error;
            }

            if (member.status === "suspended") {
                const error = new Error(
                    "This membership is suspended. Please contact the club before renewing."
                );
                error.statusCode = 403;
                throw error;
            }

            const consumeResult = await otps.updateOne(
                {
                    _id: otpRecord._id,
                    verificationTokenHash: tokenHash,
                    verified: true,
                    consumedAt: { $exists: false },
                    expiresAt: { $gt: now }
                },
                {
                    $set: { consumedAt: now },
                    $unset: { verificationTokenHash: "" }
                },
                { session }
            );

            if (consumeResult.modifiedCount !== 1) {
                const error = new Error(
                    "Verification token has already been used. Please verify your email again."
                );
                error.statusCode = 401;
                throw error;
            }

            const purchase = {
                memberId: member.memberId,

                customer: {
                    fullName: member.fullName,
                    email: member.email,
                    phone: member.phone,
                    dateOfBirth: member.dateOfBirth
                },

                plan: normalizedPlan,
                amount: plan.amount,
                currency: plan.currency,
                durationMonths: plan.durationMonths,

                purchaseType: "renewal",
                paymentStatus: "pending",
                paymentGateway: "stripe",

                stripeSessionId: null,
                stripePaymentIntentId: null,

                purchasedAt: now,
                membershipStartDate: null,
                membershipExpiryDate: null,

                createdAt: now,
                updatedAt: now
            };

            const result = await purchases.insertOne(purchase, { session });

            renewalPurchase = {
                purchaseId: result.insertedId,
                memberId: member.memberId,
                plan: plan.name,
                amount: plan.amount,
                currency: plan.currency,
                durationMonths: plan.durationMonths
            };
        });

        return res.status(201).json({
            success: true,
            message: "Renewal purchase created successfully. Continue to payment.",
            ...renewalPurchase
        });

    } catch (error) {
        console.error("Renewal purchase error:", error);

        return res.status(error.statusCode || 500).json({
            success: false,
            message: error.statusCode
                ? error.message
                : "Unable to create renewal purchase."
        });

    } finally {
        await session.endSession();
    }
});

// ==========================================
// STRIPE CHECKOUT
// ==========================================


app.post("/api/payments/create-checkout-session", checkoutLimiter, async (req, res) => {
    try {
        if (!stripe) {
            return res.status(503).json({
                success: false,
                message: "Stripe is not configured yet."
            });
        }

        const { purchaseId } = req.body;

        if (
            typeof purchaseId !== "string" ||
            !ObjectId.isValid(purchaseId)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid purchase ID."
            });
        }

        const purchases = db.collection("purchases");

        const purchase = await purchases.findOne({
            _id: new ObjectId(purchaseId),
            paymentStatus: "pending"
        });

        if (!purchase) {
            return res.status(404).json({
                success: false,
                message: "Pending purchase not found."
            });
        }

        const plan = membershipPlans[purchase.plan];

        if (
            !plan ||
            purchase.amount !== plan.amount ||
            purchase.currency !== plan.currency
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid purchase details."
            });
        }

        // Reuse an existing Stripe Checkout Session if possible.
        let idempotencyKey = `checkout-${purchase._id}-initial`;

        if (purchase.stripeSessionId) {
            const existingSession =
                await stripe.checkout.sessions.retrieve(
                    purchase.stripeSessionId
                );

            if (
                existingSession.status === "open" &&
                existingSession.url
            ) {
                return res.json({
                    success: true,
                    checkoutUrl: existingSession.url
                });
            }

            if (existingSession.status === "complete") {
                return res.status(409).json({
                    success: false,
                    message: "This checkout session has already been completed or is processing."
                });
            }

            if (existingSession.status !== "expired") {
                return res.status(409).json({
                    success: false,
                    message: "Unable to create another checkout session for this purchase."
                });
            }

            // Use the expired session ID to create a new,
            // consistent idempotency key for this retry.
            idempotencyKey =
                `checkout-${purchase._id}-${existingSession.id}`;
        }

        const stripeSession = await stripe.checkout.sessions.create(
            {
                mode: "payment",

                customer_email: purchase.customer.email,

                line_items: [
                    {
                        price_data: {
                            currency: purchase.currency,
                            unit_amount: purchase.amount,
                            product_data: {
                                name: `${plan.name} Membership`,
                                description: `${plan.durationMonths} month membership`
                            }
                        },
                        quantity: 1
                    }
                ],

                metadata: {
                    purchaseId: purchase._id.toString()
                },

                payment_intent_data: {
                    metadata: {
                        purchaseId: purchase._id.toString()
                    }
                },

                success_url: `${FRONTEND_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,

                cancel_url: `${FRONTEND_URL}/payment/cancelled`
            },
            {
                idempotencyKey
            }
        );

        if (!stripeSession.url) {
            return res.status(500).json({
                success: false,
                message: "Stripe did not return a checkout URL."
            });
        }

        const updateResult = await purchases.updateOne(
            {
                _id: purchase._id,
                paymentStatus: "pending"
            },
            {
                $set: {
                    stripeSessionId: stripeSession.id,
                    updatedAt: new Date()
                }
            }
        );

        if (updateResult.modifiedCount !== 1) {
            const latestPurchase = await purchases.findOne({
                _id: purchase._id
            });

            if (
                !latestPurchase ||
                latestPurchase.paymentStatus !== "pending"
            ) {
                return res.status(409).json({
                    success: false,
                    message: "This purchase is no longer pending."
                });
            }

            if (latestPurchase.stripeSessionId !== stripeSession.id) {
                return res.status(409).json({
                    success: false,
                    message: "The checkout session changed. Please try again."
                });
            }
        }

        return res.json({
            success: true,
            checkoutUrl: stripeSession.url
        });

    } catch (error) {
        console.error("Stripe checkout error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to create checkout session."
        });
    }
});


// ==========================================
// ACTIVATE VERIFIED PAID PURCHASE
// ==========================================


const activatePaidPurchase = async (purchaseId) => {
    if (
        typeof purchaseId !== "string" ||
        !ObjectId.isValid(purchaseId)
    ) {
        throw new Error("Invalid purchase ID.");
    }

    const session = client.startSession();

    let activationResult = null;
    let membershipEmail = null;

    try {
        await session.withTransaction(async () => {
            const purchases = db.collection("purchases");
            const members = db.collection("members");

            const purchase = await purchases.findOne(
                {
                    _id: new ObjectId(purchaseId),
                    paymentStatus: "paid"
                },
                { session }
            );

            if (!purchase) {
                throw new Error("Verified paid purchase not found.");
            }

            // Prevent duplicate activation and duplicate emails
            // when Stripe sends the same webhook more than once.
            if (
                purchase.membershipActivatedAt ||
                purchase.membershipActivationStatus === "completed"
            ) {
                activationResult = {
                    success: true,
                    message: "Membership already activated.",
                    memberId: purchase.memberId
                };

                return;
            }

            const plan = membershipPlans[purchase.plan];

            if (
                !plan ||
                purchase.amount !== plan.amount ||
                purchase.currency !== plan.currency
            ) {
                throw new Error("Purchase plan validation failed.");
            }

            let member = await members.findOne(
                { email: purchase.customer.email },
                { session }
            );

            const isNewMember = !member;
            const now = new Date();

            const startDate =
                member?.expiryDate && member.expiryDate > now
                    ? member.expiryDate
                    : now;

            const expiryDate = addCalendarMonths(
                startDate,
                plan.durationMonths
            );

            // Generate a new secure card link for this email.
            const cardToken = randomBytes(32).toString("hex");
            const cardTokenHash = hashToken(cardToken);

            if (isNewMember) {
                const newMember = {
                    memberId: generateMemberId(),

                    // Preserve the original token field.
                    accessTokenHash: cardTokenHash,

                    // Keep all card token hashes so previous links
                    // continue working after future renewals.
                    cardAccessTokenHashes: [cardTokenHash],

                    fullName: purchase.customer.fullName,
                    email: purchase.customer.email,
                    phone: purchase.customer.phone,
                    dateOfBirth: purchase.customer.dateOfBirth,

                    membershipType: purchase.plan,
                    membershipStartDate: startDate,
                    expiryDate,

                    status: "active",

                    createdAt: now,
                    updatedAt: now
                };

                const result = await members.insertOne(
                    newMember,
                    { session }
                );

                member = {
                    ...newMember,
                    _id: result.insertedId
                };

            } else {
                const memberUpdate = await members.updateOne(
                    { _id: member._id },
                    {
                        $set: {
                            fullName: purchase.customer.fullName,
                            phone: purchase.customer.phone,
                            dateOfBirth: purchase.customer.dateOfBirth,
                            membershipType: purchase.plan,
                            membershipStartDate: startDate,
                            expiryDate,
                            status: member.status === "suspended"
                                ? "suspended"
                                : "active",
                            updatedAt: now
                        },

                        // Add the new card token without removing
                        // any previously issued card tokens.
                        $addToSet: {
                            cardAccessTokenHashes: cardTokenHash
                        }
                    },
                    { session }
                );

                if (memberUpdate.matchedCount !== 1) {
                    throw new Error("Member update failed.");
                }
            }

            const activationUpdate = await purchases.updateOne(
                {
                    _id: purchase._id,
                    paymentStatus: "paid",
                    membershipActivationStatus: {
                        $ne: "completed"
                    },
                    membershipActivatedAt: {
                        $exists: false
                    }
                },
                {
                    $set: {
                        memberId: member.memberId,
                        membershipStartDate: startDate,
                        membershipExpiryDate: expiryDate,
                        membershipActivatedAt: now,
                        membershipActivationStatus: "completed",
                        updatedAt: now
                    }
                },
                { session }
            );

            if (activationUpdate.modifiedCount !== 1) {
                throw new Error(
                    "Purchase activation could not be completed."
                );
            }

            // Prepare the email only after all activation updates
            // have succeeded inside the transaction.
            membershipEmail = {
                email: member.email,
                fullName: member.fullName,
                memberId: member.memberId,
                cardToken,
                planName: plan.name,
                amount: purchase.amount,
                currency: purchase.currency,
                expiryDate,
                isNewMember
            };

            activationResult = {
                success: true,
                memberId: member.memberId
            };
        });

        // Send the email after the database transaction commits.
        if (membershipEmail) {
            const escapeHTML = (value) =>
                String(value ?? "").replace(
                    /[&<>"']/g,
                    (character) => ({
                        "&": "&amp;",
                        "<": "&lt;",
                        ">": "&gt;",
                        '"': "&quot;",
                        "'": "&#39;"
                    })[character]
                );

            const cardUrl =
                `${FRONTEND_URL}/member/${membershipEmail.cardToken}`;

            const formattedAmount =
                `${(membershipEmail.amount / 100).toFixed(2)} ${membershipEmail.currency.toUpperCase()}`;

            const formattedExpiry =
                membershipEmail.expiryDate.toDateString();

            const subject = membershipEmail.isNewMember
                ? "Welcome to DA WEB SOCIAL CLUB"
                : "Your DA WEB SOCIAL CLUB Membership Has Been Renewed";

            const heading = membershipEmail.isNewMember
                ? "Welcome to DA WEB SOCIAL CLUB"
                : "Membership Successfully Renewed";

            const message = membershipEmail.isNewMember
                ? "Your membership has been successfully activated."
                : "Your payment was successful and your membership has been successfully renewed.";

            try {
                const emailResult = await resend.emails.send({
                    from: process.env.EMAIL_FROM,
                    to: membershipEmail.email,
                    subject,

                    html: `
                        <div style="
                            background:#080808;
                            color:#ffffff;
                            padding:35px 20px;
                            font-family:Arial,sans-serif;
                            text-align:center;
                        ">
                            <h1 style="
                                color:#d4af37;
                                margin-bottom:25px;
                            ">
                                ${heading}
                            </h1>

                            <p style="color:#dddddd;">
                                Hello ${escapeHTML(membershipEmail.fullName)},
                            </p>

                            <p style="
                                color:#dddddd;
                                line-height:1.7;
                            ">
                                ${message}
                            </p>

                            <div style="
                                background:#151515;
                                border:1px solid #444;
                                border-radius:10px;
                                padding:25px;
                                margin:25px auto;
                                max-width:420px;
                                text-align:left;
                            ">
                                <p>
                                    <span style="color:#aaaaaa;">
                                        Member ID:
                                    </span>
                                    <strong>
                                        ${escapeHTML(membershipEmail.memberId)}
                                    </strong>
                                </p>

                                <p>
                                    <span style="color:#aaaaaa;">
                                        Membership:
                                    </span>
                                    <strong style="color:#d4af37;">
                                        ${escapeHTML(membershipEmail.planName)}
                                    </strong>
                                </p>

                                <p>
                                    <span style="color:#aaaaaa;">
                                        Payment:
                                    </span>
                                    <strong>${escapeHTML(formattedAmount)}</strong>
                                </p>

                                <p>
                                    <span style="color:#aaaaaa;">
                                        Membership Expiry:
                                    </span>
                                    <strong>${escapeHTML(formattedExpiry)}</strong>
                                </p>
                            </div>

                            <a
                                href="${cardUrl}"
                                style="
                                    display:inline-block;
                                    padding:14px 28px;
                                    background:#d4af37;
                                    color:#080808;
                                    text-decoration:none;
                                    font-weight:bold;
                                    border-radius:5px;
                                    margin-top:10px;
                                "
                            >
                                VIEW YOUR MEMBERSHIP CARD
                            </a>

                            <p style="
                                color:#888888;
                                font-size:12px;
                                margin-top:35px;
                            ">
                                DA WEB SOCIAL CLUB
                            </p>
                        </div>
                    `
                });

                if (emailResult.error) {
                    console.error(
                        "Membership activated, but email failed:",
                        emailResult.error
                    );
                } else {
                    console.log(
                        membershipEmail.isNewMember
                            ? "Welcome email sent successfully."
                            : "Renewal confirmation email sent successfully."
                    );
                }

            } catch (emailError) {
                console.error(
                    "Membership activated, but email sending failed:",
                    emailError
                );
            }
        }

        return activationResult;

    } finally {
        await session.endSession();
    }
};


// ==========================================
// STRIPE WEBHOOK
// ==========================================


app.post("/api/stripe/webhook", async (req, res) => {
    const signature = req.headers["stripe-signature"];

    if (!stripe) {
        return res.status(503).send("Stripe is not configured.");
    }

    if (!process.env.STRIPE_WEBHOOK_SECRET) {
        return res.status(503).send("Stripe webhook secret is missing.");
    }

    if (!req.rawBody || !signature) {
        return res.status(400).send("Missing webhook signature or raw body.");
    }

    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.rawBody,
            signature,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (error) {
        console.error("Stripe webhook signature error:", error.message);

        return res.status(400).send("Invalid webhook signature.");
    }

    try {
        if (
            event.type === "checkout.session.completed" ||
            event.type === "checkout.session.async_payment_succeeded"
        ) {
            const checkoutSession = event.data.object;

            // Validate the Stripe Checkout Session.
            if (
                checkoutSession.mode !== "payment" ||
                checkoutSession.status !== "complete"
            ) {
                return res.status(400).json({
                    received: false,
                    message: "Invalid checkout session."
                });
            }

            if (checkoutSession.payment_status !== "paid") {
                return res.json({
                    received: true,
                    message: "Payment is not completed yet."
                });
            }

            const purchaseId = checkoutSession.metadata?.purchaseId;

            if (
                typeof purchaseId !== "string" ||
                !ObjectId.isValid(purchaseId)
            ) {
                console.error("Invalid purchase ID in Stripe metadata.");

                return res.status(400).json({
                    received: false,
                    message: "Invalid purchase reference."
                });
            }

            const purchases = db.collection("purchases");

            const purchase = await purchases.findOne({
                _id: new ObjectId(purchaseId),
                stripeSessionId: checkoutSession.id
            });

            if (!purchase) {
                console.error(
                    "Purchase not found for Stripe session:",
                    checkoutSession.id
                );

                return res.status(404).json({
                    received: false,
                    message: "Purchase not found."
                });
            }

            const plan = membershipPlans[purchase.plan];

            if (
                !plan ||
                purchase.amount !== plan.amount ||
                purchase.currency !== plan.currency ||
                checkoutSession.amount_total !== purchase.amount ||
                checkoutSession.currency !== purchase.currency
            ) {
                console.error(
                    "Stripe payment details mismatch:",
                    purchaseId
                );

                return res.status(400).json({
                    received: false,
                    message: "Payment amount or currency mismatch."
                });
            }

            // Update payment status only if it is still pending.
            await purchases.updateOne(
                {
                    _id: purchase._id,
                    paymentStatus: "pending",
                    stripeSessionId: checkoutSession.id
                },
                {
                    $set: {
                        paymentStatus: "paid",
                        stripePaymentIntentId:
                            typeof checkoutSession.payment_intent === "string"
                                ? checkoutSession.payment_intent
                                : checkoutSession.payment_intent?.id || null,
                        paidAt: new Date(),
                        updatedAt: new Date()
                    }
                }
            );

            // Fetch the latest purchase to handle duplicate webhook events.
            const updatedPurchase = await purchases.findOne({
                _id: purchase._id,
                paymentStatus: "paid",
                stripeSessionId: checkoutSession.id
            });

            if (updatedPurchase) {
                const result = await activatePaidPurchase(purchaseId);

                console.log(
                    "Membership activation result:",
                    result
                );
            }
        }

        if (event.type === "checkout.session.expired") {
            const checkoutSession = event.data.object;

            console.log(
                "Stripe Checkout Session expired:",
                checkoutSession.id
            );

            // Keep the purchase pending.
            // The checkout route will detect the expired session
            // and create a new Checkout Session when requested.
        }

        return res.json({ received: true });

    } catch (error) {
        console.error("Stripe webhook processing error:", error);

        return res.status(500).json({
            received: false,
            message: "Webhook processing failed."
        });
    }
});

app.get("/api/payments/confirmation/:sessionId", async (req, res) => {
    try {
        if (!stripe) {
            return res.status(503).json({
                success: false,
                message: "Stripe is not configured."
            });
        }

        if (!process.env.JWT_SECRET) {
            return res.status(503).json({
                success: false,
                message: "Server security configuration is missing."
            });
        }

        const { sessionId } = req.params;

        if (
            typeof sessionId !== "string" ||
            !/^cs_(test|live)_[A-Za-z0-9]+$/.test(sessionId)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid checkout session ID."
            });
        }

        // Verify the checkout session directly with Stripe.
        const checkoutSession =
            await stripe.checkout.sessions.retrieve(sessionId);

        if (
            checkoutSession.status !== "complete" ||
            checkoutSession.payment_status !== "paid"
        ) {
            return res.status(202).json({
                success: true,
                status: "processing",
                message: "Waiting for payment confirmation."
            });
        }

        const purchase = await db.collection("purchases").findOne({
            stripeSessionId: sessionId
        });

        if (!purchase) {
            return res.status(404).json({
                success: false,
                message: "Purchase not found."
            });
        }

        // Ensure the Stripe session belongs to this purchase.
        if (
            checkoutSession.metadata?.purchaseId !==
            purchase._id.toString() ||
            checkoutSession.amount_total !== purchase.amount ||
            checkoutSession.currency !== purchase.currency
        ) {
            return res.status(400).json({
                success: false,
                message: "Payment details could not be verified."
            });
        }

        // The webhook must finish activating the membership first.
        if (
            purchase.paymentStatus !== "paid" ||
            (
                purchase.membershipActivationStatus !== "completed" &&
                !purchase.membershipActivatedAt
            )
        ) {
            return res.status(202).json({
                success: true,
                status: "processing",
                message: "Your membership is being activated."
            });
        }

        const members = db.collection("members");

        const member = await members.findOne({
            memberId: purchase.memberId
        });

        if (!member) {
            return res.status(202).json({
                success: true,
                status: "processing",
                message: "Preparing your membership card."
            });
        }

        // Generate the same secure token for this purchase every time.
        // The raw token is never stored in MongoDB.
        const cardToken = hashToken(
            `payment-card:${sessionId}:${process.env.JWT_SECRET}`
        );

        const cardTokenHash = hashToken(cardToken);

        // Register the token hash while preserving previous card links.
        await members.updateOne(
            { _id: member._id },
            {
                $addToSet: {
                    cardAccessTokenHashes: cardTokenHash
                }
            }
        );

        const frontendUrl = FRONTEND_URL.replace(/\/+$/, "");

        return res.json({
            success: true,
            status: "completed",
            cardUrl: `${frontendUrl}/member/${cardToken}`
        });

    } catch (error) {
        console.error("Payment confirmation error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to confirm your membership yet."
        });
    }
});


// ==========================================
// DIGITAL MEMBERSHIP CARD
// ==========================================

app.get("/api/members/card/:token", async (req, res) => {
    try {
        const token = req.params.token;

        if (!/^[a-f0-9]{64}$/i.test(token)) {
            return res.status(404).json({
                success: false,
                message: "Membership card not found."
            });
        }

        const tokenHash = hashToken(token);

        const member = await db.collection("members").findOne({
            $or: [
                {
                    accessTokenHash: tokenHash
                },
                {
                    cardAccessTokenHashes: tokenHash
                }
            ]
        });

        if (!member) {
            return res.status(404).json({
                success: false,
                message: "Membership card not found."
            });
        }

        let membershipStatus = "active";

        if (member.status === "suspended") {
            membershipStatus = "suspended";
        } else if (member.expiryDate <= new Date()) {
            membershipStatus = "expired";
        }

        return res.json({
            success: true,
            member: {
                memberId: member.memberId,
                fullName: member.fullName,
                membershipType: member.membershipType,
                membershipStartDate: member.membershipStartDate,
                expiryDate: member.expiryDate,
                membershipStatus
            }
        });

    } catch (error) {
        console.error("Membership card error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve membership card."
        });
    }
});



/* ==========================================
   ADMIN DASHBOARD APIs
========================================== */

// ==========================================
// DASHBOARD STATISTICS
// ==========================================

app.get("/api/admin/dashboard/stats", verifyAdmin, async (req, res) => {
    try {
        const members = db.collection("members");
        const purchases = db.collection("purchases");

        const now = new Date();

        const [
            totalMembers,
            activeMembers,
            expiredMembers,
            suspendedMembers,
            totalPurchases,
            paidPurchases,
            pendingPurchases,
            revenueResult
        ] = await Promise.all([
            members.countDocuments(),

            members.countDocuments({
                status: { $ne: "suspended" },
                expiryDate: { $gt: now }
            }),

            members.countDocuments({
                status: { $ne: "suspended" },
                expiryDate: { $lte: now }
            }),

            members.countDocuments({
                status: "suspended"
            }),

            purchases.countDocuments(),

            purchases.countDocuments({
                paymentStatus: "paid"
            }),

            purchases.countDocuments({
                paymentStatus: "pending"
            }),

            purchases.aggregate([
                {
                    $match: {
                        paymentStatus: "paid"
                    }
                },
                {
                    $group: {
                        _id: null,
                        totalRevenue: { $sum: "$amount" }
                    }
                }
            ]).toArray()
        ]);

        return res.json({
            success: true,
            stats: {
                totalMembers,
                activeMembers,
                expiredMembers,
                suspendedMembers,
                totalPurchases,
                paidPurchases,
                pendingPurchases,
                totalRevenue: revenueResult[0]?.totalRevenue || 0,
                currency: "USD"
            }
        });

    } catch (error) {
        console.error("Dashboard statistics error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve dashboard statistics."
        });
    }
});

// ==========================================
// GET ALL MEMBERS
// Search + Pagination + Filtering
// ==========================================


app.get("/api/admin/members", verifyAdmin, async (req, res) => {
    try {
        const requestedPage = req.query.page === undefined
            ? 1
            : Number(req.query.page);

        const requestedLimit = req.query.limit === undefined
            ? 10
            : Number(req.query.limit);

        if (
            !Number.isSafeInteger(requestedPage) ||
            requestedPage < 1 ||
            !Number.isSafeInteger(requestedLimit) ||
            requestedLimit < 1
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid pagination parameters."
            });
        }

        const limit = Math.min(50, requestedLimit);

        const search = typeof req.query.search === "string"
            ? req.query.search.trim()
            : "";

        const status = typeof req.query.status === "string"
            ? req.query.status.trim().toLowerCase()
            : "";

        const membership = typeof req.query.membership === "string"
            ? req.query.membership.trim().toLowerCase()
            : "";

        if (search.length > 100) {
            return res.status(400).json({
                success: false,
                message: "Search query is too long."
            });
        }

        if (
            status &&
            !["all", "active", "expired", "suspended"].includes(status)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid membership status filter."
            });
        }

        if (
            membership &&
            !["all", "basic", "premium", "vip"].includes(membership)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid membership filter."
            });
        }

        const filter = {};

        if (search) {
            const escapedSearch = search.replace(
                /[.*+?^${}()|[\]\\]/g,
                "\\$&"
            );

            filter.$or = [
                { fullName: { $regex: escapedSearch, $options: "i" } },
                { email: { $regex: escapedSearch, $options: "i" } },
                { memberId: { $regex: escapedSearch, $options: "i" } }
            ];
        }

        if (membership && membership !== "all") {
            filter.membershipType = membership;
        }

        const now = new Date();

        if (status === "active") {
            filter.status = { $ne: "suspended" };
            filter.expiryDate = { $gt: now };
        } else if (status === "expired") {
            filter.status = { $ne: "suspended" };
            filter.expiryDate = { $lte: now };
        } else if (status === "suspended") {
            filter.status = "suspended";
        }

        const membersCollection = db.collection("members");

        const totalMembers = await membersCollection.countDocuments(filter);

        const totalPages = Math.ceil(totalMembers / limit);

        const page = Math.min(
            requestedPage,
            Math.max(1, totalPages)
        );

        const members = await membersCollection.find(
            filter,
            {
                projection: {
                    accessTokenHash: 0
                }
            }
        )
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .toArray();

        const formattedMembers = members.map(member => {
            let membershipStatus = "active";

            if (member.status === "suspended") {
                membershipStatus = "suspended";
            } else if (
                !member.expiryDate ||
                member.expiryDate <= now
            ) {
                membershipStatus = "expired";
            }

            return {
                ...member,
                membershipStatus
            };
        });

        return res.json({
            success: true,
            members: formattedMembers,
            pagination: {
                currentPage: page,
                totalPages,
                totalMembers,
                limit
            }
        });

    } catch (error) {
        console.error("Admin members error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve members."
        });
    }
});


// ==========================================
// GET SINGLE MEMBER DETAILS
// ==========================================


app.get("/api/admin/members/:memberId", verifyAdmin, async (req, res) => {
    try {
        const memberId = typeof req.params.memberId === "string"
            ? req.params.memberId.trim()
            : "";

        if (!memberId || memberId.length > 50) {
            return res.status(400).json({
                success: false,
                message: "Invalid member ID."
            });
        }

        const member = await db.collection("members").findOne(
            { memberId },
            {
                projection: {
                    accessTokenHash: 0
                }
            }
        );

        if (!member) {
            return res.status(404).json({
                success: false,
                message: "Member not found."
            });
        }

        const now = new Date();

        let membershipStatus = "active";

        if (member.status === "suspended") {
            membershipStatus = "suspended";
        } else if (
            !member.expiryDate ||
            member.expiryDate <= now
        ) {
            membershipStatus = "expired";
        }

        const purchaseHistory = await db.collection("purchases")
            .find(
                { memberId },
                {
                    projection: {
                        customer: 0,
                        stripeSessionId: 0,
                        stripePaymentIntentId: 0
                    }
                }
            )
            .sort({ purchasedAt: -1 })
            .limit(20)
            .toArray();

        return res.json({
            success: true,
            member: {
                ...member,
                membershipStatus
            },
            purchaseHistory
        });

    } catch (error) {
        console.error("Member details error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve member details."
        });
    }
});


// ==========================================
// SUSPEND / REACTIVATE MEMBER
// ==========================================


app.patch("/api/admin/members/:memberId/status", verifyAdmin, async (req, res) => {
    try {
        const memberId = typeof req.params.memberId === "string"
            ? req.params.memberId.trim()
            : "";

        const status = req.body?.status;

        if (!memberId || memberId.length > 50) {
            return res.status(400).json({
                success: false,
                message: "Invalid member ID."
            });
        }

        if (
            typeof status !== "string" ||
            !["active", "suspended"].includes(status)
        ) {
            return res.status(400).json({
                success: false,
                message: "Status must be either active or suspended."
            });
        }

        const result = await db.collection("members").updateOne(
            { memberId },
            {
                $set: {
                    status,
                    updatedAt: new Date(),
                    statusUpdatedBy: req.admin.id
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: "Member not found."
            });
        }

        return res.json({
            success: true,
            message: status === "suspended"
                ? "Membership suspended successfully."
                : "Membership reactivated successfully.",
            status
        });

    } catch (error) {
        console.error("Member status update error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to update membership status."
        });
    }
});


// ==========================================
// GET MEMBER PURCHASE HISTORY
// ==========================================

app.get("/api/admin/members/:memberId/purchases", verifyAdmin, async (req, res) => {
    try {
        const { memberId } = req.params;

        const member = await db.collection("members").findOne(
            { memberId },
            {
                projection: {
                    memberId: 1,
                    fullName: 1,
                    email: 1
                }
            }
        );

        if (!member) {
            return res.status(404).json({
                success: false,
                message: "Member not found."
            });
        }

        const purchases = await db.collection("purchases")
            .find({ memberId })
            .sort({ purchasedAt: -1 })
            .toArray();

        return res.json({
            success: true,
            member,
            totalPurchases: purchases.length,
            purchases
        });

    } catch (error) {
        console.error("Purchase history error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve purchase history."
        });
    }
});

// ==========================================
// GET RECENT PURCHASES
// ==========================================

app.get("/api/admin/purchases/recent", verifyAdmin, async (req, res) => {
    try {
        const limit = Math.min(
            50,
            Math.max(1, Number.parseInt(req.query.limit) || 10)
        );

        const purchases = await db.collection("purchases")
            .find({})
            .sort({ purchasedAt: -1 })
            .limit(limit)
            .toArray();

        return res.json({
            success: true,
            purchases
        });

    } catch (error) {
        console.error("Recent purchases error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve recent purchases."
        });
    }
});


// ==========================================
// CENTRAL ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
    console.error("Server error:", error.message);

    if (res.headersSent) {
        return next(error);
    }

    if (error.type === "entity.too.large") {
        return res.status(413).json({
            success: false,
            message: "Request body is too large."
        });
    }

    if (
        error instanceof SyntaxError &&
        error.status === 400 &&
        "body" in error
    ) {
        return res.status(400).json({
            success: false,
            message: "Invalid JSON request body."
        });
    }

    if (error.message === "Not allowed by CORS") {
        return res.status(403).json({
            success: false,
            message: "This origin is not allowed."
        });
    }

    return res.status(500).json({
        success: false,
        message: "An internal server error occurred."
    });
});


// ==========================================
// START SERVER 
// ==========================================

const startServer = async () => {
    try {
        await connectDB();

        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });

    } catch (error) {
        console.error("Server startup failed:", error);
        process.exit(1);
    }
};

startServer();