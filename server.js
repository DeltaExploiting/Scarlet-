import express from "express";
import multer from "multer";
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 3000;
const SERVICE_TOKEN = process.env.SIGNING_SERVICE_TOKEN;
const jobs = new Map();

const upload = multer({ dest: "/tmp/uploads", limits: { fileSize: 1024 * 1024 * 1024 } });

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!SERVICE_TOKEN || !token) return res.status(401).json({ error: "Unauthorized" });
  const a = Buffer.from(token);
  const b = Buffer.from(SERVICE_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: "Unauthorized" });
  next();
}

app.get("/health", async (_req, res) => {
  try {
    await execFileAsync("zsign", ["-v"]);
    res.json({ status: "ok", zsignAvailable: true });
  } catch {
    res.status(500).json({ status: "error", zsignAvailable: false });
  }
});

app.post("/api/sign", authenticate, upload.fields([
  { name: "ipa", maxCount: 1 },
  { name: "p12", maxCount: 1 },
  { name: "mobileprovision", maxCount: 1 }
]), async (req, res) => {
  const jobId = crypto.randomUUID();
  const jobDir = path.join("/tmp", `signing-${jobId}`);
  const ipa = req.files?.ipa?.[0];
  const p12 = req.files?.p12?.[0];
  const profile = req.files?.mobileprovision?.[0];
  const password = req.body?.password;

  try {
    if (!ipa || !p12 || !profile || !password) throw new Error("Missing required signing files or password");
    jobs.set(jobId, { status: "signing", progress: 50, currentStep: "Signing application" });
    await fs.mkdir(jobDir, { recursive: true });
    const outputPath = path.join(jobDir, "signed.ipa");
    await execFileAsync("zsign", ["-k", p12.path, "-m", profile.path, "-o", outputPath, "-p", password, ipa.path]);
    jobs.set(jobId, { status: "completed", progress: 100, currentStep: "Complete", outputPath });
    res.json({ status: "completed", jobId, downloadPath: `/api/download/${jobId}` });
  } catch (error) {
    jobs.set(jobId, { status: "failed", progress: 0, error: error.message });
    res.status(500).json({ status: "failed", jobId, error: error.message });
  } finally {
    setTimeout(async () => {
      const job = jobs.get(jobId);
      await fs.rm(job?.outputPath || jobDir, { recursive: true, force: true }).catch(() => {});
      await fs.rm(jobDir, { recursive: true, force: true }).catch(() => {});
      await Promise.all([ipa?.path, p12?.path, profile?.path].filter(Boolean).map(p => fs.rm(p, { force: true }).catch(() => {})));
      jobs.delete(jobId);
    }, 10 * 60 * 1000).unref();
  }
});

app.get("/api/jobs/:jobId", authenticate, (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const { outputPath, ...safeJob } = job;
  res.json({ jobId: req.params.jobId, ...safeJob });
});

app.get("/api/download/:jobId", authenticate, async (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job?.outputPath) return res.status(404).json({ error: "Signed file not available" });
  try { await fs.access(job.outputPath); } catch { return res.status(404).json({ error: "Signed file expired" }); }
  res.download(job.outputPath, "signed.ipa");
});

app.listen(PORT, "0.0.0.0", () => console.log(`Signing server listening on ${PORT}`));
