import express from "express";

const app = express();

app.get("/", (req, res) => {
  res.send("Meraki Splash Server Çalışıyor 🚀");
});

app.listen(process.env.PORT || 3000, () =>
  console.log("Server started")
);
