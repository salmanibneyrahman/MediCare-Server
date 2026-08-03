const dns = require("node:dns");
dns.setServers(["1.1.1.1", "8.8.8.8"]);

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
    cors({
        origin: [
            "http://localhost:3000",
            process.env.FRONTEND_URL || "http://localhost:3000",
        ],
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

app.use(express.json());

// ─── MONGODB CONNECTION ───────────────────────
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

let usersCollection;
let doctorsCollection;
let appointmentsCollection;
let reviewsCollection;
let paymentsCollection;
let prescriptionsCollection;
let isConnected = false;

async function connectDB() {
    if (isConnected) return;

    try {
        await client.connect();
        const db = client.db("MediCare");
        usersCollection = db.collection("user");
        doctorsCollection = db.collection("doctors");
        appointmentsCollection = db.collection("appointments");
        reviewsCollection = db.collection("reviews");
        paymentsCollection = db.collection("payments");
        prescriptionsCollection = db.collection("prescriptions");
        isConnected = true;
        console.log("Connected to MongoDB Atlas - MediCare Database");
    } catch (error) {
        console.error("MongoDB connection error:", error);
        throw error;
    }
}

// Connect on startup
connectDB().catch(err => {
    console.error("Failed to connect to MongoDB:", err);
});

// Middleware to ensure DB connection
const ensureDB = async (req, res, next) => {
    try {
        if (!isConnected) {
            await connectDB();
        }
        next();
    } catch (error) {
        res.status(500).json({ error: "Database connection failed" });
    }
};

// Apply DB middleware to all routes
app.use(ensureDB);

// ─── JWKS-BASED JWT VERIFICATION ─────────────
const { createRemoteJWKSet, jwtVerify } = require("jose");

const JWKS_URL = process.env.FRONTEND_URL
    ? `${process.env.FRONTEND_URL}/api/auth/jwks`
    : "http://localhost:3000/api/auth/jwks";

let remoteJWKS = null;

function getRemoteJWKS() {
    if (!remoteJWKS) {
        remoteJWKS = createRemoteJWKSet(new URL(JWKS_URL), {
            cacheMaxAge: 10 * 60 * 1000,
        });
    }
    return remoteJWKS;
}

async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res
            .status(401)
            .json({ error: "Unauthorized: No token provided" });
    }
    const token = authHeader.split(" ")[1];
    try {
        const JWKS = getRemoteJWKS();
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: process.env.FRONTEND_URL || "http://localhost:3000",
        });
        req.user = payload;
        next();
    } catch (err) {
        console.error("Token verification error:", err.message);
        return res
            .status(403)
            .json({ error: "Forbidden: Invalid or expired token" });
    }
}

// ─── ROLE GUARDS ──────────────────────────────
async function verifyAdmin(req, res, next) {
    try {
        const email = req.user?.email;
        if (!email) return res.status(403).json({ error: "Forbidden" });
        const user = await usersCollection.findOne({ email });
        if (!user || user.role !== "admin") {
            return res.status(403).json({ error: "Forbidden: Admins only" });
        }
        next();
    } catch {
        return res.status(500).json({ error: "Server error" });
    }
}

async function verifyDoctor(req, res, next) {
    try {
        const email = req.user?.email;
        if (!email) return res.status(403).json({ error: "Forbidden" });
        const user = await usersCollection.findOne({ email });
        if (!user || (user.role !== "doctor" && user.role !== "admin")) {
            return res.status(403).json({ error: "Forbidden: Doctors only" });
        }
        next();
    } catch {
        return res.status(500).json({ error: "Server error" });
    }
}

// ─── HEALTH CHECK ─────────────────────────────
app.get("/", (req, res) => {
    res.status(200).json({ message: "MediCare Connect API is running" });
});

// ─────────────────────────────────────────────
// USERS
// ─────────────────────────────────────────────

app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const users = await usersCollection.find({}).toArray();
        res.status(200).json(users);
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/users/:email", verifyToken, async (req, res) => {
    try {
        const { email } = req.params;
        const tokenEmail = req.user?.email;
        const requestingUser = await usersCollection.findOne({
            email: tokenEmail,
        });
        const isAdmin = requestingUser?.role === "admin";
        if (tokenEmail !== email && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });
        res.status(200).json(user);
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/api/users", async (req, res) => {
    try {
        const { name, email, photo, phone, gender, role } = req.body;
        if (!name || !email) {
            return res
                .status(400)
                .json({ error: "Name and email are required" });
        }

        const allowedSelfRoles = ["patient", "doctor"];
        const requestedRole = allowedSelfRoles.includes(role) ? role : null;

        const existingUser = await usersCollection.findOne({ email });

        if (existingUser) {
            const patch = {};

            if (phone && !existingUser.phone) patch.phone = phone;
            if (gender && !existingUser.gender) patch.gender = gender;
            if (photo && !existingUser.photo) patch.photo = photo;
            if (name && !existingUser.name) patch.name = name;
            if (!existingUser.status) patch.status = "active";
            if (!existingUser.createdAt) patch.createdAt = new Date();

            if (existingUser.role !== "admin") {
                if (requestedRole && existingUser.role !== requestedRole) {
                    patch.role = requestedRole;
                } else if (!existingUser.role) {
                    patch.role = "patient";
                }
            }

            if (Object.keys(patch).length > 0) {
                await usersCollection.updateOne({ email }, { $set: patch });
            }

            const user = await usersCollection.findOne({ email });
            return res.status(200).json({
                message: "User already exists",
                existing: true,
                user,
            });
        }

        const newUser = {
            name,
            email,
            photo: photo || "",
            phone: phone || "",
            gender: gender || "",
            role: requestedRole || "patient",
            status: "active",
            createdAt: new Date(),
        };
        const result = await usersCollection.insertOne(newUser);
        const user = await usersCollection.findOne({
            _id: result.insertedId,
        });

        res.status(201).json({
            message: "User created successfully",
            insertedId: result.insertedId,
            user,
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/api/users/:email", verifyToken, async (req, res) => {
    try {
        const { email } = req.params;
        const tokenEmail = req.user?.email;
        const requestingUser = await usersCollection.findOne({
            email: tokenEmail,
        });
        const isAdmin = requestingUser?.role === "admin";
        if (tokenEmail !== email && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const updateData = { ...req.body };
        delete updateData._id;
        delete updateData.email;
        if (!isAdmin) delete updateData.role;
        const result = await usersCollection.updateOne(
            { email },
            { $set: updateData }
        );
        res
            .status(200)
            .json({ message: "User updated successfully", result });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.delete("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid user ID" });
        }
        const result = await usersCollection.deleteOne({
            _id: new ObjectId(id),
        });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }
        res.status(200).json({ message: "User deleted successfully" });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch(
    "/api/users/:id/status",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const { id } = req.params;
            const { status } = req.body;
            if (!ObjectId.isValid(id)) {
                return res.status(400).json({ error: "Invalid user ID" });
            }
            const allowedStatuses = ["active", "suspended"];
            if (!allowedStatuses.includes(status)) {
                return res.status(400).json({ error: "Invalid status" });
            }
            const result = await usersCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { status } }
            );
            if (result.matchedCount === 0) {
                return res.status(404).json({ error: "User not found" });
            }
            res
                .status(200)
                .json({ message: `User ${status} successfully` });
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

// ─────────────────────────────────────────────
// DOCTORS
// ─────────────────────────────────────────────

app.get("/api/doctors", async (req, res) => {
    try {
        const {
            search,
            specialization,
            sortBy,
            page = 1,
            limit = 9,
            includeUnverified = "true",
        } = req.query;

        let query = {};

        if (includeUnverified === "true") {
            query.verificationStatus = { $in: ["verified", "pending"] };
        } else {
            query.verificationStatus = "verified";
        }

        if (search) {
            query.$or = [
                { doctorName: { $regex: search, $options: "i" } },
                { specialization: { $regex: search, $options: "i" } },
                { hospitalName: { $regex: search, $options: "i" } },
            ];
        }
        if (specialization && specialization !== "all") {
            query.specialization = { $regex: specialization, $options: "i" };
        }

        let sortOptions = {};
        if (sortBy === "fee_asc") sortOptions = { consultationFee: 1 };
        else if (sortBy === "fee_desc") sortOptions = { consultationFee: -1 };
        else if (sortBy === "experience") sortOptions = { experience: -1 };
        else if (sortBy === "rating") sortOptions = { averageRating: -1 };
        else sortOptions = { createdAt: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await doctorsCollection.countDocuments(query);
        const doctors = await doctorsCollection
            .aggregate([
                { $match: query },
                {
                    $addFields: {
                        isVerified: {
                            $eq: ["$verificationStatus", "verified"],
                        },
                    },
                },
                { $sort: { isVerified: -1, ...sortOptions } },
                { $skip: skip },
                { $limit: parseInt(limit) },
            ])
            .toArray();

        res.status(200).json({
            doctors,
            total,
            page: parseInt(page),
            totalPages: Math.ceil(total / parseInt(limit)),
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get(
    "/api/admin/doctors",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const doctors = await doctorsCollection
                .find({})
                .sort({ createdAt: -1 })
                .toArray();
            res.status(200).json(doctors);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.get(
    "/api/doctors/profile/:email",
    verifyToken,
    async (req, res) => {
        try {
            const { email } = req.params;
            const tokenEmail = req.user?.email;
            const requestingUser = await usersCollection.findOne({
                email: tokenEmail,
            });
            const isAdmin = requestingUser?.role === "admin";
            if (tokenEmail !== email && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const doctor = await doctorsCollection.findOne({ email });
            if (!doctor) {
                return res
                    .status(404)
                    .json({ error: "Doctor profile not found" });
            }
            res.status(200).json(doctor);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.get("/api/doctors/featured", async (req, res) => {
    try {
        const doctors = await doctorsCollection
            .find({ verificationStatus: "verified" })
            .sort({ averageRating: -1 })
            .limit(6)
            .toArray();
        res.status(200).json(doctors);
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/doctors/:id", async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid doctor ID" });
        }
        const doctor = await doctorsCollection.findOne({
            _id: new ObjectId(id),
        });
        if (!doctor) {
            return res.status(404).json({ error: "Doctor not found" });
        }
        res.status(200).json(doctor);
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/api/doctors", verifyToken, async (req, res) => {
    try {
        const tokenEmail = req.user?.email;
        const doctorData = req.body;
        if (!doctorData.doctorName || !doctorData.specialization) {
            return res
                .status(400)
                .json({ error: "Name and specialization are required" });
        }
        const existing = await doctorsCollection.findOne({
            email: tokenEmail,
        });
        if (existing) {
            return res
                .status(409)
                .json({ error: "Doctor profile already exists" });
        }
        let profileImage = doctorData.profileImage || "";
        if (!profileImage) {
            const account = await usersCollection.findOne({
                email: tokenEmail,
            });
            profileImage = account?.photo || account?.image || "";
        }

        const newDoctor = {
            ...doctorData,
            email: tokenEmail,
            profileImage,
            verificationStatus: "pending",
            averageRating: 0,
            totalReviews: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
        };
        const result = await doctorsCollection.insertOne(newDoctor);
        res.status(201).json({
            message: "Doctor profile created successfully",
            insertedId: result.insertedId,
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/api/doctors/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const tokenEmail = req.user?.email;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid doctor ID" });
        }
        const doctor = await doctorsCollection.findOne({
            _id: new ObjectId(id),
        });
        if (!doctor) {
            return res.status(404).json({ error: "Doctor not found" });
        }
        const requestingUser = await usersCollection.findOne({
            email: tokenEmail,
        });
        const isAdmin = requestingUser?.role === "admin";
        if (doctor.email !== tokenEmail && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const updateData = { ...req.body, updatedAt: new Date() };
        delete updateData._id;
        const result = await doctorsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );
        res
            .status(200)
            .json({ message: "Doctor updated successfully", result });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch(
    "/api/doctors/:id/verify",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const { id } = req.params;
            const { status } = req.body;
            if (!ObjectId.isValid(id)) {
                return res.status(400).json({ error: "Invalid doctor ID" });
            }
            const allowedStatuses = ["verified", "rejected", "pending"];
            if (!allowedStatuses.includes(status)) {
                return res
                    .status(400)
                    .json({ error: "Invalid verification status" });
            }
            const result = await doctorsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        verificationStatus: status,
                        updatedAt: new Date(),
                    },
                }
            );
            if (result.matchedCount === 0) {
                return res.status(404).json({ error: "Doctor not found" });
            }
            if (status === "verified") {
                const doctor = await doctorsCollection.findOne({
                    _id: new ObjectId(id),
                });
                if (doctor?.email) {
                    await usersCollection.updateOne(
                        { email: doctor.email },
                        { $set: { role: "doctor" } }
                    );
                }
            }
            res
                .status(200)
                .json({ message: "Doctor verification status updated" });
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

// ─────────────────────────────────────────────
// APPOINTMENTS
// ─────────────────────────────────────────────

app.get(
    "/api/appointments",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const appointments = await appointmentsCollection
                .find({})
                .sort({ createdAt: -1 })
                .toArray();
            res.status(200).json(appointments);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.get(
    "/api/appointments/patient/:patientId",
    verifyToken,
    async (req, res) => {
        try {
            const { patientId } = req.params;
            const tokenEmail = req.user?.email;
            const user = await usersCollection.findOne({ email: tokenEmail });
            const isAdmin = user?.role === "admin";
            if (user?._id?.toString() !== patientId && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const appointments = await appointmentsCollection
                .find({ patientId })
                .sort({ createdAt: -1 })
                .toArray();
            res.status(200).json(appointments);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.get(
    "/api/appointments/doctor/:doctorId",
    verifyToken,
    verifyDoctor,
    async (req, res) => {
        try {
            const { doctorId } = req.params;
            const tokenEmail = req.user?.email;
            const user = await usersCollection.findOne({ email: tokenEmail });
            const isAdmin = user?.role === "admin";
            const doctorDoc = await doctorsCollection.findOne({
                email: tokenEmail,
            });
            const isOwner = doctorDoc?._id?.toString() === doctorId;
            if (!isOwner && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const appointments = await appointmentsCollection
                .find({ doctorId })
                .sort({ createdAt: -1 })
                .toArray();
            res.status(200).json(appointments);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.post("/api/appointments", verifyToken, async (req, res) => {
    try {
        const {
            patientId,
            patientName,
            patientEmail,
            doctorId,
            doctorName,
            specialization,
            consultationFee,
            appointmentDate,
            appointmentTime,
            symptoms,
        } = req.body;
        const tokenEmail = req.user?.email;
        if (tokenEmail !== patientEmail) {
            return res.status(403).json({ error: "Forbidden" });
        }
        if (!patientId || !doctorId || !appointmentDate || !appointmentTime) {
            return res
                .status(400)
                .json({ error: "Required fields missing" });
        }

        // Get patient info
        const patientDoc = await usersCollection.findOne({ email: patientEmail });

        const newAppointment = {
            patientId,
            patientName: patientName || "",
            patientEmail: patientEmail || "",
            patientPhoto: patientDoc?.photo || patientDoc?.image || "",
            doctorId,
            doctorName: doctorName || "",
            specialization: specialization || "",
            consultationFee: parseFloat(consultationFee) || 0,
            appointmentDate,
            appointmentTime,
            symptoms: symptoms || "",
            appointmentStatus: "pending",
            paymentStatus: "unpaid",
            createdAt: new Date(),
            updatedAt: new Date(),
        };
        const result =
            await appointmentsCollection.insertOne(newAppointment);
        res.status(201).json({
            message: "Appointment created successfully",
            insertedId: result.insertedId,
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/api/appointments/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const tokenEmail = req.user?.email;
        if (!ObjectId.isValid(id)) {
            return res
                .status(400)
                .json({ error: "Invalid appointment ID" });
        }
        const appointment = await appointmentsCollection.findOne({
            _id: new ObjectId(id),
        });
        if (!appointment) {
            return res
                .status(404)
                .json({ error: "Appointment not found" });
        }
        const requestingUser = await usersCollection.findOne({
            email: tokenEmail,
        });
        const isAdmin = requestingUser?.role === "admin";
        const isPatient = appointment.patientEmail === tokenEmail;
        const doctorDoc = await doctorsCollection.findOne({
            email: tokenEmail,
        });
        const isDoctor =
            appointment.doctorId === doctorDoc?._id?.toString();
        if (!isPatient && !isDoctor && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const updateData = { ...req.body, updatedAt: new Date() };
        delete updateData._id;
        const result = await appointmentsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );
        res
            .status(200)
            .json({ message: "Appointment updated successfully", result });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.delete(
    "/api/appointments/:id",
    verifyToken,
    async (req, res) => {
        try {
            const { id } = req.params;
            const tokenEmail = req.user?.email;
            if (!ObjectId.isValid(id)) {
                return res
                    .status(400)
                    .json({ error: "Invalid appointment ID" });
            }
            const appointment = await appointmentsCollection.findOne({
                _id: new ObjectId(id),
            });
            if (!appointment) {
                return res
                    .status(404)
                    .json({ error: "Appointment not found" });
            }
            const requestingUser = await usersCollection.findOne({
                email: tokenEmail,
            });
            const isAdmin = requestingUser?.role === "admin";
            const isPatient = appointment.patientEmail === tokenEmail;
            if (!isPatient && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            await appointmentsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        appointmentStatus: "cancelled",
                        updatedAt: new Date(),
                    },
                }
            );
            res
                .status(200)
                .json({ message: "Appointment cancelled successfully" });
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

// ─────────────────────────────────────────────
// REVIEWS
// ─────────────────────────────────────────────

app.get("/api/reviews", async (req, res) => {
    try {
        const reviews = await reviewsCollection
            .find({})
            .sort({ createdAt: -1 })
            .limit(10)
            .toArray();
        res.status(200).json(reviews);
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/reviews/doctor/:doctorId", async (req, res) => {
    try {
        const { doctorId } = req.params;
        const reviews = await reviewsCollection
            .find({ doctorId })
            .sort({ createdAt: -1 })
            .toArray();
        res.status(200).json(reviews);
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get(
    "/api/reviews/patient/:patientId",
    verifyToken,
    async (req, res) => {
        try {
            const { patientId } = req.params;
            const tokenEmail = req.user?.email;
            const user = await usersCollection.findOne({ email: tokenEmail });
            const isAdmin = user?.role === "admin";
            if (user?._id?.toString() !== patientId && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const reviews = await reviewsCollection
                .find({ patientId })
                .sort({ createdAt: -1 })
                .toArray();
            res.status(200).json(reviews);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.post("/api/reviews", verifyToken, async (req, res) => {
    try {
        const {
            patientId,
            doctorId,
            rating,
            reviewText,
            patientName,
            doctorName,
        } = req.body;
        const tokenEmail = req.user?.email;
        if (!patientId || !doctorId || !rating) {
            return res
                .status(400)
                .json({ error: "Required fields missing" });
        }
        if (parseInt(rating) < 1 || parseInt(rating) > 5) {
            return res
                .status(400)
                .json({ error: "Rating must be between 1 and 5" });
        }
        const user = await usersCollection.findOne({ email: tokenEmail });
        if (user?._id?.toString() !== patientId) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const newReview = {
            patientId,
            patientName: patientName || user?.name || "",
            patientPhoto: user?.photo || user?.image || "",
            doctorId,
            doctorName: doctorName || "",
            rating: parseInt(rating),
            reviewText: reviewText || "",
            createdAt: new Date(),
        };
        const result = await reviewsCollection.insertOne(newReview);
        const allReviews = await reviewsCollection
            .find({ doctorId })
            .toArray();
        const avgRating =
            allReviews.reduce((sum, r) => sum + r.rating, 0) /
            allReviews.length;
        if (ObjectId.isValid(doctorId)) {
            await doctorsCollection.updateOne(
                { _id: new ObjectId(doctorId) },
                {
                    $set: {
                        averageRating: parseFloat(avgRating.toFixed(1)),
                        totalReviews: allReviews.length,
                    },
                }
            );
        }
        res.status(201).json({
            message: "Review added successfully",
            insertedId: result.insertedId,
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/api/reviews/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { rating, reviewText } = req.body;
        const tokenEmail = req.user?.email;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid review ID" });
        }
        if (parseInt(rating) < 1 || parseInt(rating) > 5) {
            return res
                .status(400)
                .json({ error: "Rating must be between 1 and 5" });
        }
        const review = await reviewsCollection.findOne({
            _id: new ObjectId(id),
        });
        if (!review) {
            return res.status(404).json({ error: "Review not found" });
        }
        const user = await usersCollection.findOne({ email: tokenEmail });
        const isAdmin = user?.role === "admin";
        if (review.patientId !== user?._id?.toString() && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }
        await reviewsCollection.updateOne(
            { _id: new ObjectId(id) },
            {
                $set: {
                    rating: parseInt(rating),
                    reviewText: reviewText || "",
                    updatedAt: new Date(),
                },
            }
        );
        const allReviews = await reviewsCollection
            .find({ doctorId: review.doctorId })
            .toArray();
        const avgRating =
            allReviews.reduce((sum, r) => sum + r.rating, 0) /
            allReviews.length;
        if (ObjectId.isValid(review.doctorId)) {
            await doctorsCollection.updateOne(
                { _id: new ObjectId(review.doctorId) },
                {
                    $set: {
                        averageRating: parseFloat(avgRating.toFixed(1)),
                        totalReviews: allReviews.length,
                    },
                }
            );
        }
        res.status(200).json({ message: "Review updated successfully" });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.delete("/api/reviews/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const tokenEmail = req.user?.email;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid review ID" });
        }
        const review = await reviewsCollection.findOne({
            _id: new ObjectId(id),
        });
        if (!review) {
            return res.status(404).json({ error: "Review not found" });
        }
        const user = await usersCollection.findOne({ email: tokenEmail });
        const isAdmin = user?.role === "admin";
        if (review.patientId !== user?._id?.toString() && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }
        await reviewsCollection.deleteOne({ _id: new ObjectId(id) });
        const allReviews = await reviewsCollection
            .find({ doctorId: review.doctorId })
            .toArray();
        if (ObjectId.isValid(review.doctorId)) {
            const avgRating =
                allReviews.length > 0
                    ? allReviews.reduce((sum, r) => sum + r.rating, 0) /
                    allReviews.length
                    : 0;
            await doctorsCollection.updateOne(
                { _id: new ObjectId(review.doctorId) },
                {
                    $set: {
                        averageRating: parseFloat(avgRating.toFixed(1)),
                        totalReviews: allReviews.length,
                    },
                }
            );
        }
        res.status(200).json({ message: "Review deleted successfully" });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

// ─────────────────────────────────────────────
// PAYMENTS
// ─────────────────────────────────────────────

app.get(
    "/api/payments",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const payments = await paymentsCollection
                .find({})
                .sort({ paymentDate: -1 })
                .toArray();
            res.status(200).json(payments);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.get(
    "/api/payments/patient/:patientId",
    verifyToken,
    async (req, res) => {
        try {
            const { patientId } = req.params;
            const tokenEmail = req.user?.email;
            const user = await usersCollection.findOne({ email: tokenEmail });
            const isAdmin = user?.role === "admin";
            if (user?._id?.toString() !== patientId && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const payments = await paymentsCollection
                .find({ patientId })
                .sort({ paymentDate: -1 })
                .toArray();
            res.status(200).json(payments);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.post("/api/payments", verifyToken, async (req, res) => {
    try {
        const {
            appointmentId,
            patientId,
            doctorId,
            amount,
            transactionId,
        } = req.body;
        const tokenEmail = req.user?.email;
        if (!appointmentId || !patientId || !amount || !transactionId) {
            return res
                .status(400)
                .json({ error: "Required fields missing" });
        }
        const user = await usersCollection.findOne({ email: tokenEmail });
        if (user?._id?.toString() !== patientId) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const existingPayment = await paymentsCollection.findOne({
            appointmentId,
        });
        if (existingPayment) {
            return res.status(409).json({
                error: "Payment already recorded for this appointment",
            });
        }

        // Get appointment info
        const apptDoc = await appointmentsCollection.findOne({
            _id: new ObjectId(appointmentId),
        });

        const payment = {
            appointmentId,
            patientId,
            patientName: apptDoc?.patientName || "",
            patientEmail: apptDoc?.patientEmail || "",
            doctorId: doctorId || "",
            doctorName: apptDoc?.doctorName || "",
            amount: parseFloat(amount),
            transactionId,
            paymentMethod: "stripe",
            paymentDate: new Date(),
        };
        const result = await paymentsCollection.insertOne(payment);
        if (ObjectId.isValid(appointmentId)) {
            await appointmentsCollection.updateOne(
                { _id: new ObjectId(appointmentId) },
                {
                    $set: {
                        paymentStatus: "paid",
                        appointmentStatus: "confirmed",
                        updatedAt: new Date(),
                    },
                }
            );
        }
        res.status(201).json({
            message: "Payment recorded successfully",
            insertedId: result.insertedId,
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

// ─────────────────────────────────────────────
// STRIPE
// ─────────────────────────────────────────────

const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.post(
    "/api/stripe/create-payment-intent",
    verifyToken,
    async (req, res) => {
        try {
            const { amount, appointmentId, patientId, doctorId } = req.body;
            if (!amount || !appointmentId || !patientId) {
                return res
                    .status(400)
                    .json({ error: "Missing required fields" });
            }
            const amountInCents = Math.round(parseFloat(amount) * 100);
            if (amountInCents < 50) {
                return res
                    .status(400)
                    .json({ error: "Amount must be at least $0.50" });
            }
            const paymentIntent = await stripe.paymentIntents.create({
                amount: amountInCents,
                currency: "usd",
                automatic_payment_methods: { enabled: true },
                metadata: {
                    appointmentId,
                    patientId,
                    doctorId: doctorId || "",
                },
            });
            res.status(200).json({
                clientSecret: paymentIntent.client_secret,
                paymentIntentId: paymentIntent.id,
            });
        } catch (error) {
            res
                .status(500)
                .json({ error: error.message || "Stripe error" });
        }
    }
);

app.post(
    "/api/stripe/confirm-payment",
    verifyToken,
    async (req, res) => {
        try {
            const {
                paymentIntentId,
                appointmentId,
                patientId,
                doctorId,
                amount,
            } = req.body;
            if (!paymentIntentId || !appointmentId || !patientId) {
                return res
                    .status(400)
                    .json({ error: "Missing required fields" });
            }
            const paymentIntent =
                await stripe.paymentIntents.retrieve(paymentIntentId);
            if (paymentIntent.status !== "succeeded") {
                return res
                    .status(400)
                    .json({ error: "Payment not completed on Stripe" });
            }
            const existingPayment = await paymentsCollection.findOne({
                transactionId: paymentIntentId,
            });
            if (existingPayment) {
                return res
                    .status(409)
                    .json({ error: "Payment already recorded" });
            }

            // Get appointment info
            const apptDoc = await appointmentsCollection.findOne({
                _id: new ObjectId(appointmentId),
            });

            const payment = {
                appointmentId,
                patientId,
                patientName: apptDoc?.patientName || "",
                patientEmail: apptDoc?.patientEmail || "",
                doctorId: doctorId || "",
                doctorName: apptDoc?.doctorName || "",
                amount: parseFloat(amount),
                transactionId: paymentIntentId,
                paymentMethod: "stripe",
                paymentDate: new Date(),
            };
            const result = await paymentsCollection.insertOne(payment);
            if (ObjectId.isValid(appointmentId)) {
                await appointmentsCollection.updateOne(
                    { _id: new ObjectId(appointmentId) },
                    {
                        $set: {
                            paymentStatus: "paid",
                            appointmentStatus: "confirmed",
                            updatedAt: new Date(),
                        },
                    }
                );
            }
            res.status(201).json({
                message: "Payment confirmed and recorded successfully",
                insertedId: result.insertedId,
            });
        } catch (error) {
            res
                .status(500)
                .json({ error: error.message || "Confirmation error" });
        }
    }
);

// ─────────────────────────────────────────────
// PRESCRIPTIONS
// ─────────────────────────────────────────────

app.get(
    "/api/prescriptions/appointment/:appointmentId",
    verifyToken,
    async (req, res) => {
        try {
            const { appointmentId } = req.params;
            const tokenEmail = req.user?.email;
            const appointment = await appointmentsCollection.findOne(
                ObjectId.isValid(appointmentId)
                    ? { _id: new ObjectId(appointmentId) }
                    : { _id: null }
            );
            const user = await usersCollection.findOne({ email: tokenEmail });
            const isAdmin = user?.role === "admin";
            const isPatient = appointment?.patientEmail === tokenEmail;
            const doctorDoc = await doctorsCollection.findOne({
                email: tokenEmail,
            });
            const isDoctor =
                appointment?.doctorId === doctorDoc?._id?.toString();
            if (!isPatient && !isDoctor && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const prescription = await prescriptionsCollection.findOne({
                appointmentId,
            });
            res.status(200).json(prescription || null);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.get(
    "/api/prescriptions/patient/:patientId",
    verifyToken,
    async (req, res) => {
        try {
            const { patientId } = req.params;
            const tokenEmail = req.user?.email;
            const user = await usersCollection.findOne({ email: tokenEmail });
            const isAdmin = user?.role === "admin";
            if (user?._id?.toString() !== patientId && !isAdmin) {
                return res.status(403).json({ error: "Forbidden" });
            }
            const prescriptions = await prescriptionsCollection
                .find({ patientId })
                .sort({ createdAt: -1 })
                .toArray();
            res.status(200).json(prescriptions);
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.post(
    "/api/prescriptions",
    verifyToken,
    verifyDoctor,
    async (req, res) => {
        try {
            const {
                doctorId,
                patientId,
                appointmentId,
                diagnosis,
                medications,
                notes,
            } = req.body;
            if (!doctorId || !patientId || !appointmentId || !diagnosis) {
                return res
                    .status(400)
                    .json({ error: "Required fields missing" });
            }
            const existing = await prescriptionsCollection.findOne({
                appointmentId,
            });
            if (existing) {
                return res.status(409).json({
                    error:
                        "Prescription already exists for this appointment",
                });
            }
            const prescription = {
                doctorId,
                patientId,
                appointmentId,
                diagnosis,
                medications: medications || "",
                notes: notes || "",
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            const result =
                await prescriptionsCollection.insertOne(prescription);
            res.status(201).json({
                message: "Prescription created successfully",
                insertedId: result.insertedId,
            });
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

app.patch(
    "/api/prescriptions/:id",
    verifyToken,
    verifyDoctor,
    async (req, res) => {
        try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) {
                return res
                    .status(400)
                    .json({ error: "Invalid prescription ID" });
            }
            const prescription = await prescriptionsCollection.findOne({
                _id: new ObjectId(id),
            });
            if (!prescription) {
                return res
                    .status(404)
                    .json({ error: "Prescription not found" });
            }
            const updateData = {
                ...req.body,
                updatedAt: new Date(),
            };
            delete updateData._id;
            const result = await prescriptionsCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: updateData }
            );
            res.status(200).json({
                message: "Prescription updated successfully",
                result,
            });
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

// ─────────────────────────────────────────────
// STATISTICS & ANALYTICS
// ─────────────────────────────────────────────

app.get("/api/stats", async (req, res) => {
    try {
        const [
            totalDoctors,
            totalPatients,
            totalAppointments,
            totalReviews,
        ] = await Promise.all([
            doctorsCollection.countDocuments({
                verificationStatus: "verified",
            }),
            usersCollection.countDocuments({ role: "patient" }),
            appointmentsCollection.countDocuments({}),
            reviewsCollection.countDocuments({}),
        ]);
        res.status(200).json({
            totalDoctors,
            totalPatients,
            totalAppointments,
            totalReviews,
        });
    } catch {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get(
    "/api/admin/analytics",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        try {
            const [
                totalDoctors,
                totalPatients,
                totalAppointments,
                totalPayments,
                doctorPerformance,
                appointmentsByStatus,
                monthlyAppointments,
            ] = await Promise.all([
                doctorsCollection.countDocuments({}),
                usersCollection.countDocuments({ role: "patient" }),
                appointmentsCollection.countDocuments({}),
                paymentsCollection.find({}).toArray(),
                doctorsCollection
                    .find({ verificationStatus: "verified" })
                    .sort({ averageRating: -1 })
                    .limit(10)
                    .project({
                        doctorName: 1,
                        averageRating: 1,
                        totalReviews: 1,
                        specialization: 1,
                    })
                    .toArray(),
                appointmentsCollection
                    .aggregate([
                        {
                            $group: {
                                _id: "$appointmentStatus",
                                count: { $sum: 1 },
                            },
                        },
                    ])
                    .toArray(),
                appointmentsCollection
                    .aggregate([
                        {
                            $group: {
                                _id: {
                                    month: { $month: "$createdAt" },
                                    year: { $year: "$createdAt" },
                                },
                                count: { $sum: 1 },
                            },
                        },
                        { $sort: { "_id.year": 1, "_id.month": 1 } },
                        { $limit: 12 },
                    ])
                    .toArray(),
            ]);
            const totalRevenue = totalPayments.reduce(
                (sum, p) => sum + (p.amount || 0),
                0
            );
            res.status(200).json({
                totalDoctors,
                totalPatients,
                totalAppointments,
                totalRevenue,
                doctorPerformance,
                appointmentsByStatus,
                monthlyAppointments,
            });
        } catch {
            res.status(500).json({ error: "Internal server error" });
        }
    }
);

// ─── 404 HANDLER ──────────────────────────────
app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

// ─── START SERVER ─────────────────────────────
if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => {
        console.log(`MediCare Connect API running on port ${PORT}`);
        console.log(`JWKS endpoint: ${JWKS_URL}`);
    });
}

module.exports = app;