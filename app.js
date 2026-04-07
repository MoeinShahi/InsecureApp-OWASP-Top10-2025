const express = require("express");
const multer = require("multer");
const sharp = require("sharp");
const auth = require("string-utils");

const app = express();

// serve frontend
app.use(express.static("."));
app.use(express.static("public"));

// parse form data
app.use(express.urlencoded({ extended: true }));

// login route
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const isAuth = auth.authenticate(username, password);

    if (isAuth) {
        // Redirect to convert page with success query
        res.redirect("public/convert.html?login=success"); 
    } else {
        res.send("Invalid credentials. <a href='/'>Go back</a>");
    }
});

const upload = multer({ dest: "uploads/" });

app.post("/convert", upload.single("file"), async (req, res) => {
    const inputPath = req.file.path;
    const outputPath = "converted/output.png";

    // Force crash on unsupported file type or corrupt file
    await sharp(inputPath).png().toFile(outputPath)
        .then(() => {
            res.download(outputPath);
        });
        //.catch(err => {
         //   console.error("A10 demo crash! Invalid file:", err.message);
            // crash the server intentionally for demo
           // process.exit(1);
        //});
});
// start server
app.listen(3000, () => console.log("Server running on port 3000"));
