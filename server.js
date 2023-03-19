const express = require("express");
const bodyParser = require("body-parser");
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");
const uuid = require("uuid");
const speakeasy = require("speakeasy");
const app = express();
app.use(express.json());
const db = new JsonDB(new Config("Data", true, false, "/"));

app.get("/api", (req, res) => {
  res.status(200).json({ message: "Welcome to Two factor authentication API" });
});

app.post("/api/register", (req, res) => {
  const id = uuid.v4();
  try {
    const path = `/users/${id}`;
    const temp_secret = speakeasy.generateSecret();
    db.push(path, { id, temp_secret });
    res.status(200).json({ id, secret: temp_secret.base32 });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error generating the secret" });
  }
});

app.post("/api/verify", async (req, res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/users/${userId}`;
    const user = await db.getData(path);
    console.log({ user }, token);
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
    });
    console.log(verified);
    if (verified) {
      // Update user data
      await db.push(path, { id: userId, secret: user.temp_secret });
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving user" });
  }
});
app.post("/api/validate", async (req, res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/users/${userId}`;
    const user = await db.getData(path);
    const { base32: secret } = user.secret;
    const validated = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });
    res.json({ valid: validated });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving user" });
  }
});
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
