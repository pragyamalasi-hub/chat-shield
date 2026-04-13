// =============================================================================
// server.js — Chat Shield API Server
// Express backend exposing /analyze-prompt REST endpoint
// =============================================================================

const express = require("express");
const cors = require("cors");
const { analyzePrompt, rewritePrompt } = require("./detector");

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors()); // Allow requests from React frontend
app.use(express.json()); // Parse JSON request bodies

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "Chat Shield API is running 🛡️", version: "1.0.0" });
});

// =============================================================================
// POST /analyze-prompt
// Main endpoint: receives a prompt and returns classification + analysis
//
// Request body: { prompt: string }
// Response:     {
//   classification: "SAFE" | "SUSPICIOUS" | "ADVERSARIAL",
//   confidence: number (0–1),
//   reasons: Array<{ label, weight, severity }>,
//   highlights: Array<{ start, end, label, severity, text }>,
//   scores: { semantic, keyword, encoding },
//   processingTime: number (ms)
// }
// =============================================================================
app.post("/analyze-prompt", (req, res) => {
  const startTime = Date.now();

  const { prompt } = req.body;

  // Validate input
  if (typeof prompt !== "string") {
    return res.status(400).json({ error: "Request body must include a 'prompt' string field." });
  }

  // Limit prompt length to prevent abuse
  if (prompt.length > 5000) {
    return res.status(400).json({ error: "Prompt too long. Maximum 5000 characters." });
  }

  try {
    // Run detection pipeline
    const result = analyzePrompt(prompt);

    const processingTime = Date.now() - startTime;

    return res.json({
      ...result,
      processingTime,
    });
  } catch (err) {
    console.error("Analysis error:", err);
    return res.status(500).json({ error: "Internal analysis error." });
  }
});

// =============================================================================
// POST /rewrite-prompt
// Bonus endpoint: rewrites an unsafe prompt into a safe version
//
// Request body: { prompt: string }
// Response:     { original: string, rewritten: string, analysis: object }
// =============================================================================
app.post("/rewrite-prompt", (req, res) => {
  const { prompt } = req.body;

  if (typeof prompt !== "string") {
    return res.status(400).json({ error: "Request body must include a 'prompt' string field." });
  }

  try {
    const analysis = analyzePrompt(prompt);
    const rewritten = rewritePrompt(prompt);
    const rewrittenAnalysis = analyzePrompt(rewritten);

    return res.json({
      original: prompt,
      rewritten,
      originalAnalysis: analysis,
      rewrittenAnalysis,
    });
  } catch (err) {
    console.error("Rewrite error:", err);
    return res.status(500).json({ error: "Internal rewrite error." });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  Chat Shield API running on http://localhost:${PORT}`);
  console.log(`   POST /analyze-prompt — analyze a prompt`);
  console.log(`   POST /rewrite-prompt — rewrite an unsafe prompt\n`);
});
