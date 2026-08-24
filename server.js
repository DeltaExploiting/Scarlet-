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

const upload = multer({
  dest: "/tmp/uploads",
  limits: { fileSize: 1024 * 1024 * 1024 }
});

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!SERVICE_TOKEN || !token || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(SERVICE_TOKEN))) {
    return res.status(401).json({ error: "Unauthorized" });
  }
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

  jobs.set(jobId, { status: "validating", progress: 20, currentStep: "Validating files" });

  try {
    if (!ipa || !p12 || !profile || !password) throw new Error("Missing required signing files or password");
    await fs.mkdir(jobDir, { recursive: true });
    const outputPath = path.join(jobDir, "signed.ipa");
    jobs.set(jobId, { status: "signing", progress: 60, currentStep: "Signing application" });

    await execFileAsync("zsign", ["-k", p12.path, "-m", profile.path, "-o", outputPath, "-p", password, ipa.path]);
    jobs.set(jobId, { status: "completed", progress: 100, currentStep: "Complete" });
    res.json({ status: "completed", jobId });
  } catch (error) {
    jobs.set(jobId, { status: "failed", progress: 0, error: error.message });
    res.status(500).json({ status: "failed", jobId, error: error.message });
  } finally {
    delete req.body?.password;
    setTimeout(async () => {
      await fs.rm(jobDir, { recursive: true, force: true }).catch(() => {});
      await Promise.all([ipa?.path, p12?.path, profile?.path].filter(Boolean).map(p => fs.rm(p, { force: true }).catch(() => {})));
      jobs.delete(jobId);
    }, 10 * 60 * 1000).unref();
  }
});

app.get("/api/jobs/:jobId", authenticate, (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: "Job not found" });
  res.json({ jobId: req.params.jobId, ...job });
});

app.listen(PORT, "0.0.0.0", () => console.log(`Signing server listening on ${PORT}`));
