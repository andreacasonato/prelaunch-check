const express = require("express");
const app = express();
app.get("/api/items", (req, res) => res.json([]));
app.post("/api/items", requireAuth, (req, res) => res.json({}));
