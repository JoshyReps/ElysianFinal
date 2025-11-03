  import express from "express";
  import pg from "pg";
  import env from "dotenv";
  import passport from "passport";
  import { Strategy } from "passport-local";
  import session from "express-session";
  import bcrypt from "bcrypt";
  import nodemailer from "nodemailer";
  import crypto from "crypto";
  import multer from "multer";
  import path from "path";


  env.config();

  const app = express();
  const port = process.env.PORT;
  const saltRounds = Number(process.env.SALT_ROUND);

  let items = []
  let trending = []

  let choc_cakes = []
  let vanilla_cakes = []
  let elegant_cakes = []
  let birthday_cakes = []

  let orderCount = 0;

  const db = new pg.Client({
      user: process.env.PG_USER,
      host : process.env.PG_HOST, 
      database : process.env.PG_DATABASE,
      password : process.env.PG_PASSWORD,
      port: process.env.PG_PORT
  });

  app.use(
      session({
          secret: process.env.SESSION_SECRET,
          resave: false,
          saveUninitialized: true,
          cookie: {
              maxAge: 24 * 60 * 60 * 1000
          }
      })
  );

  app.use(passport.session());
  app.use(passport.initialize());
  app.use(express.static("public"));
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }));

  db.connect();

  let cakeDisplay = async function () {

    try {
      const cakesRes = await db.query("SELECT * FROM cakes ORDER BY likes DESC");
      items = cakesRes.rows;
      trending = cakesRes.rows.slice(0, 8);

      const typesRes = await db.query(`
        SELECT cakes.id AS id, name, img, price, likes, type
        FROM cake_types
        JOIN cakes ON cakes.id = cake_types.cake_id
      `);

      const types = typesRes.rows;

      choc_cakes = [];
      vanilla_cakes = [];
      elegant_cakes = [];
      birthday_cakes = [];

      types.forEach((cake) => {
        if (cake.type === "Chocolate") choc_cakes.push(cake);
        if (cake.type === "Vanilla") vanilla_cakes.push(cake);
        if (cake.type === "Elegant") elegant_cakes.push(cake);
        if (cake.type === "Birthday") birthday_cakes.push(cake);
      });

    } catch (err) {
      console.log("Error in cakeDisplay:", err.stack);
    }
  };

  cakeDisplay();

  app.get("/", async (req, res) => {

      if (req.isAuthenticated()) {

          const liked = await db.query(
              "SELECT cake_id FROM likes WHERE user_id = $1",
              [req.user.id]
          );

          const likedIds = liked.rows.map(l => l.cake_id);

          if (req.user && req.user.email.trim() === process.env.ADMIN_ACCOUNT.trim()) {
            return res.redirect("/admin");
          }

          const result = await db.query(
              "SELECT count(*) AS count FROM orders WHERE users_id=$1",
              [req.user.id]
          );

          orderCount = result.rows[0].count || 0;

          res.render("index.ejs", {
              items,
              trending,
              user: req.user,
              choc_cakes,
              elegant_cakes,
              orders: orderCount,
              likedIds 
          });

      } else {
          res.render("index.ejs", {items : items, trending : trending, user : null, choc_cakes : choc_cakes, elegant_cakes : elegant_cakes});
      }   
  })


  app.get("/gallery", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 8;
    const offset = (page - 1) * limit;

    const search = req.query.search ? req.query.search.trim() : "";
    const sort = req.query.sort || "";

    let searchCondition = "";
    const values = [];

    if (search) {
      values.push(`%${search}%`);
      searchCondition = `WHERE name ILIKE $${values.length}`;
    }

    let orderBy = "likes DESC";
    switch (sort) {
      case "price_asc":
        orderBy = "price ASC";
        break;
      case "price_desc":
        orderBy = "price DESC";
        break;
      case "likes_asc":
        orderBy = "likes ASC";
        break;
      case "likes_desc":
        orderBy = "likes DESC";
        break;
    }

    const countQuery = `SELECT COUNT(*) FROM cakes ${searchCondition}`;
    const totalResult = await db.query(countQuery, values);
    const totalCakes = parseInt(totalResult.rows[0].count);
    const totalPages = Math.ceil(totalCakes / limit);

    const cakeQuery = `
      SELECT * FROM cakes
      ${searchCondition}
      ORDER BY ${orderBy}
      LIMIT $${values.length + 1} OFFSET $${values.length + 2}
    `;
    const cakeResult = await db.query(cakeQuery, [...values, limit, offset]);
    const cakes = cakeResult.rows;

    let likedIds = [];
    let orderCount = 0;

    if (req.isAuthenticated()) {
      const liked = await db.query(
        "SELECT cake_id FROM likes WHERE user_id = $1",
        [req.user.id]
      );
      likedIds = liked.rows.map((l) => l.cake_id);

      const orderRes = await db.query(
        "SELECT COUNT(*) AS count FROM orders WHERE users_id=$1",
        [req.user.id]
      );
      orderCount = Number(orderRes.rows[0].count);
    }

    res.render("gallery.ejs", {
      user: req.user || null,
      cakes,
      banner: "general",
      likedIds,
      currentPage: page,
      totalPages,
      search,
      sort,
      orders: orderCount, 
    });
  } catch (err) {
    res.status(500).send("Error loading gallery.");
  }
});




  app.post("/gallery", async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = 8;
      const offset = (page - 1) * limit;
      const type = req.body.type;

      let query = `
        SELECT cakes.*
        FROM cakes
        JOIN cake_types ON cakes.id = cake_types.cake_id
        WHERE LOWER(cake_types.type) = $1
        ORDER BY likes DESC
        LIMIT $2 OFFSET $3
      `;

      const cakeResult = await db.query(query, [type, limit, offset]);

      const countResult = await db.query(`
        SELECT COUNT(*)
        FROM cakes
        JOIN cake_types ON cakes.id = cake_types.cake_id
        WHERE LOWER(cake_types.type) = $1
      `, [type]);

      const totalCakes = parseInt(countResult.rows[0].count);
      const totalPages = Math.ceil(totalCakes / limit);

      let likedIds = [];
      if (req.isAuthenticated()) {
        const liked = await db.query("SELECT cake_id FROM likes WHERE user_id = $1", [req.user.id]);
        likedIds = liked.rows.map(l => l.cake_id);
      }

      res.render("gallery.ejs", {
        user: req.user || null,
        cakes: cakeResult.rows,
        orders: orderCount,
        banner: type,
        likedIds,
        currentPage: page,
        totalPages
      });

    } catch (err) {
      res.status(500).send("Error filtering cakes.");
    }
  });

  app.get("/custom", (req, res) => {
      res.render("custom.ejs");
  })


  app.get("/register", (req, res) => {
    let errorMessage = null;

    switch (req.query.error) {
      case "password_mismatch":
        errorMessage = "Passwords do not match.";
        break;
      case "email_exists":
        errorMessage = "This email is already registered.";
        break;
      case "hash_failed":
        errorMessage = "Error securing your password. Please try again.";
        break;
      case "server_error":
        errorMessage = "Something went wrong. Please try again.";
        break;
    }

    res.render("register.ejs", { error: errorMessage });
  });


  app.get("/login", (req, res) => {
    const errorMessage = req.query.error ? "User not found or incorrect password." : null;
    res.render("login.ejs", { error: errorMessage });
  });

  app.get("/logout", (req, res) => {
  req.logout(function (err) {
      if (err) {
      return next(err);
      }
      res.redirect("/");
  });
  });

  app.post(
    "/login",
    passport.authenticate("local", {
      failureRedirect: "/login?error=1",
      successRedirect: "/",
    })
  );


  app.post("/register", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const confirm = req.body["confirm-password"];

    if (password !== confirm) {
      res.json({ success: true });
    }

    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        return res.redirect("/register?error=email_exists");
      }

      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          return res.redirect("/register?error=hash_failed");
        }

        const verifyToken = crypto.randomBytes(32).toString("hex");

        const insertResult = await db.query(
          "INSERT INTO users (email, password, verify_token, verified) VALUES ($1, $2, $3, $4) RETURNING *",
          [username, hash, verifyToken, false]
        );

        const user = insertResult.rows[0];

        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        const verifyLink = `http://localhost:${port}/verify?token=${verifyToken}`;

        await transporter.sendMail({
          from: `"Elysian Bytes" <${process.env.EMAIL_USER}>`,
          to: username,
          subject: "Verify your Elysian Bytes account",
          html: `
            <h2>Welcome to Elysian Bytes 🎂</h2>
            <p>Please click the link below to verify your account:</p>
            <a href="${verifyLink}">${verifyLink}</a>
          `,
        });

        res.render("register.ejs", { success: true, error: null });
      });
    } catch (err) {
      res.redirect("/register?error=server_error");
    }
  });


  app.get("/verify", async (req, res) => {
    const token = req.query.token;

    try {
      const result = await db.query("SELECT * FROM users WHERE verify_token = $1", [token]);

      if (result.rows.length === 0) {
        return res.send("Invalid or expired token.");
      }

      const user = result.rows[0];

      await db.query("UPDATE users SET verified = true, verify_token = NULL WHERE id = $1", [user.id]);

      req.logIn(user, (err) => {
        if (err) return res.send("Verification successful, but login failed.");
        res.redirect("/");
      });
    } catch (err) {
      res.send("Verification failed.");
    }
  });


  passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {

      try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [username]);
      if (result.rows.length > 0) {

          const user = result.rows[0];
          const storedHashedPassword = user.password;

          if (!user.verified) {
              return cb(null, false, { message: "Please verify your email first." });
          }

          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
              return cb(err);
          } else {
              if (valid) {
              return cb(null, user);
              } else {
              return cb(null, false);
              }
          }
          });
      } else {
          return cb(null, false, { message: "User not found" });
      }
      } catch (err) {
          console.log(err);
      }
  })
  );

  passport.serializeUser((user, cb) => {
      cb(null, user.id); 
  });

  passport.deserializeUser(async (id, cb) => {
      const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
      cb(null, result.rows[0]);
  });


app.get("/order", async (req, res) => {
  try {
    if (!req.user) return res.redirect("/login");

    const user_id = req.user.id;

    const result = await db.query(`
      SELECT 
        c.id,
        c.name, 
        c.img, 
        COUNT(*) AS quantity, 
        (c.price * COUNT(*)) AS price
      FROM orders o 
      JOIN cakes c ON o.cakes_id = c.id 
      WHERE o.users_id = $1 
      GROUP BY c.id, c.name, c.img, c.price
      ORDER BY c.name
    `, [user_id]);

    const totalRes = await db.query(`
      SELECT COALESCE(SUM(c.price), 0) AS total
      FROM orders o 
      JOIN cakes c ON o.cakes_id = c.id
      WHERE o.users_id = $1
    `, [user_id]);

    const countRes = await db.query(`
      SELECT COUNT(*) AS count FROM orders WHERE users_id = $1
    `, [user_id]);

    const total = Number(totalRes.rows[0].total);
    const orderCount = Number(countRes.rows[0].count);

    res.render("order.ejs", {
      user: req.user,
      cakes: result.rows,
      total,
      orders: orderCount
    });

  } catch (err) {
    res.status(500).send("Error loading orders.");
  }
});


app.get("/my-payments", async (req, res) => {
  try {

    if (!req.user) {
      return res.redirect("/login");
    }

    const { rows: payments } = await db.query(
      `SELECT id, phone, amount, reference, proof_path, verified, status,   submitted_at 
      FROM payments 
      WHERE user_id = $1 
      ORDER BY submitted_at DESC`,
      [req.user.id]
    );

    res.render("my-payments.ejs", { user: req.user, payments, orders : orderCount});
  } catch (err) {
    res.status(500).send("Internal Server Error");
  }
});


app.post("/order", async (req, res) => {
  try {
    const userId = req.user.id;
    const { cake_id } = req.body;

    await db.query(
      `INSERT INTO orders (users_id, cakes_id) VALUES ($1, $2)`,
      [userId, cake_id]
    );

  } catch (err) {
    res.status(500).send("Error adding order");
  }
});



app.post("/order/quantity", async (req, res) => {
  const { cakeName, action } = req.body;
  if (!req.user) return res.status(401).send("Not logged in");

  try {
    const userId = req.user.id;

    const cakeRes = await db.query(
      "SELECT id, price FROM cakes WHERE name=$1",
      [cakeName]
    );
    if (cakeRes.rows.length === 0)
      return res.status(404).send("Cake not found");

    const { id: cakeId, price: unitPrice } = cakeRes.rows[0];

    if (action === "increase") {
      await db.query(
        "INSERT INTO orders (users_id, cakes_id) VALUES ($1, $2)",
        [userId, cakeId]
      );
    } else if (action === "decrease") {
      await db.query(
        `DELETE FROM orders
        WHERE id = (
        SELECT id FROM orders
        WHERE users_id=$1 AND cakes_id=$2
        ORDER BY id DESC LIMIT 1
        )`,
        [userId, cakeId]
      );
    }

    const qtyRes = await db.query(
      "SELECT COUNT(*) AS qty FROM orders WHERE users_id=$1 AND cakes_id=$2",
      [userId, cakeId]
    );
    const newQuantity = Number(qtyRes.rows[0].qty);

    const totalRes = await db.query(`
      SELECT COALESCE(SUM(c.price), 0) AS total
      FROM orders o
      JOIN cakes c ON o.cakes_id = c.id
      WHERE o.users_id=$1
    `, [userId]);
    const newTotal = Number(totalRes.rows[0].total);

    const countRes = await db.query(
      "SELECT COUNT(*) AS count FROM orders WHERE users_id=$1",
      [userId]
    );
    const orderCount = Number(countRes.rows[0].count);

    const newItemTotal = newQuantity * unitPrice;

    res.json({
      success: true,
      newQuantity,
      newItemTotal,
      newTotal,
      orderCount
    });

  } catch (err) {
    res.status(500).send("Error updating quantity");
  }
});



  app.get("/auth-check", (req, res) => {
    if (req.user) {
      res.status(200).json({ loggedIn: true });
    } else {
      res.status(401).json({ loggedIn: false });
    }
  });

  app.post("/custom-order", async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ success: false, message: "Please log in to place a custom order." });
      }

      req.session.pendingCustomOrder = req.body;
      req.session.pendingCustomOrder.user_id = req.user.id;

      res.status(200).json({
        success: true,
        message: "Custom order received. Please proceed to payment.",
        redirect: "/payment"
      });
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error" });
    }
  });


  app.post("/delete/order", async (req, res) => {
  const { cake_name } = req.body;
  const user_id = req.user && req.user.id;

  if (!user_id) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  try {
    const countBeforeRes = await db.query(`
      SELECT COUNT(*) AS count
      FROM orders o
      JOIN cakes c ON o.cakes_id = c.id
      WHERE o.users_id = $1 AND c.name = $2
    `, [user_id, cake_name]);
    const deletedCount = parseInt(countBeforeRes.rows[0].count, 10) || 0;

    await db.query(`
      DELETE FROM orders o
      USING cakes c
      WHERE o.cakes_id = c.id
      AND o.users_id = $1
      AND c.name = $2;
    `, [user_id, cake_name]);

    orderCount = Math.max(0, orderCount - deletedCount);

    const countRes = await db.query(
      "SELECT COUNT(*) AS order_count FROM orders WHERE users_id = $1",
      [user_id]
    );
    const newOrderCount = parseInt(countRes.rows[0].order_count, 10);

    const totalRes = await db.query(`
      SELECT COALESCE(SUM(c.price), 0) AS total_price
      FROM orders o
      JOIN cakes c ON o.cakes_id = c.id
      WHERE o.users_id = $1
    `, [user_id]);
    const newTotal = Number(totalRes.rows[0].total_price || 0);

    return res.json({
      success: true,
      newOrderCount,
      newTotal
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Server error" });
  }
});




  app.get("/payment", async (req, res) => {

    try {
      const orders = await db.query(
        "SELECT * FROM orders WHERE users_id = $1",
        [req.user.id]
      );

      const reviews = await db.query(`
                  SELECT 
                      c.name, 
                      c.img, 
                      COUNT(*) AS quantity, 
                      (c.price * COUNT(*)) AS price
                  FROM orders o 
                  JOIN cakes c ON o.cakes_id = c.id 
                  WHERE o.users_id = $1 
                  GROUP BY c.name, c.img, c.price`, [req.user.id]);

      let total = 0;

      reviews.rows.forEach((order) => {
          total += Number(order.price);
      })

      res.render("Payment.ejs", {
        user: req.user || null, 
        type: "normal",
        orders: orders.rows.length,
        total,
        reviews: reviews.rows
      });
    } catch (err) {
      res.status(500).send("Error loading payment page");
    }
  });


  app.post("/start-custom-payment", (req, res) => {
    req.session.customOrder = {
      name: req.body.name,
      phone: req.body.phone,
      occasion: req.body.occasion,
      flavor: req.body.flavor,
      cakeType: req.body.cakeType,
      numberCake: req.body.numberCake,
      message: req.body.message,
      date: req.body.date,
      notes: req.body.notes,
      price: req.body.price
    };

    res.json({ success: true });
  });


  app.get("/custom-payment", (req, res) => {
    const customOrder = req.session.customOrder;

    if (!customOrder) {
      return res.redirect("/custom-cake"); 
    }

    res.render("Payment.ejs", {
      user: req.user || null,
      type: "custom",
      total: customOrder.price,
    });
  });

  app.get("/item", (req, res) => {
    res.render("item.ejs");
  })


  app.post("/add", async (req, res) => {
      const { referenceid, phoneNumber } = req.body;

      try {
          await db.query(
          "INSERT INTO queue (referenceid, phone, user_id) VALUES ($1, $2, $3)", [referenceid, phoneNumber, req.user.id]);
          res.redirect("/"); 
      } catch (err) {
          res.send("Error inserting data");
      }
  });


  app.get("/custom", (req, res) => {
      res.render("custom.ejs");
  });


  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, "public/images/proofs"); 
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      const ext = path.extname(file.originalname);
      cb(null, "proof-" + uniqueSuffix + ext);  
    },
  });

  const upload = multer({ storage: storage });

  app.post("/upload", upload.single("proof"), async (req, res) => {
    try {
      const { amount, reference, phone } = req.body;
      const proofPath = "images/proofs/" + req.file.filename;
      const userId = req.user ? req.user.id : null;

      const result = await db.query(
        `INSERT INTO payments (amount, reference, phone, proof_path, submitted_at, user_id)
        VALUES ($1, $2, $3, $4, NOW(), $5)
        RETURNING *`,
        [amount, reference, phone, proofPath, userId]
      );

      const newOrder = {
        amount,
        reference,
        phone,
        imageUrl: `http://localhost:${port}/${proofPath}`, 
        customerName: req.user ? req.user.email : "Guest",
      };

      await sendOrderEmail(newOrder);

      res.json({
        success: true,
        message: "Your payment proof has been submitted. Please wait for verification."
      });
    } catch (err) {
      res.status(500).send("Error submitting payment proof.");
    }
  });



  app.post("/upload-custom", upload.single("proof"), async (req, res) => {
    try {
      const { amount, reference, phone, name, occasion, flavor, cakeType, numberCake, message, date, notes, price } = req.body;
      const proofPath = "images/proofs/" + req.file.filename;
      const userId = req.user ? req.user.id : null;

      await db.query(
        `INSERT INTO custom_orders
          (user_id, name, phone, occasion, flavor, cake_type, number_cake, message, meetup_date, notes, price)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [userId, name, phone, occasion, flavor, cakeType, numberCake, message, date, notes, price]
      );

      const newOrder = {
        amount,
        reference,
        phone,
        imageUrl: `http://localhost:${port}/${proofPath}`,
        customerName: req.user ? req.user.email : "Guest",
      };
      await sendOrderEmail(newOrder);

      res.send("✅ Custom order payment submitted successfully! Your custom cake order is now confirmed.");
    } catch (err) {
      res.status(500).send("Error submitting custom order payment proof.");
    }
  });





  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS, 
    },
  });

  async function sendOrderEmail(order) {
    const mailOptions = {
      from: `"Elysian Bytes" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: `🧾 New GCash Payment Proof from ${order.customerName || "Unknown"}`,
      html: `
        <h2>New Payment Received</h2>
        <p><b>Reference ID:</b> ${order.reference}</p>
        <p><b>Amount:</b> ₱${order.amount}</p>
        <p><b>Phone:</b> ${order.phone}</p>
        <p><b>Date:</b> ${new Date().toLocaleString()}</p>
        <p><b>Status:</b> Pending Verification</p>
        ${
          order.imageUrl
            ? `<p><b>Proof:</b> <a href="${order.imageUrl}">View Image</a></p>`
            : ""
        }
      `,
    };

    await transporter.sendMail(mailOptions);
  }



  app.get("/admin", async (req, res) => {

    if(!req.user || (req.user && req.user.email != process.env.EMAIL_USER)) {
      return res.status(403).send("Unauthorized: You do not have permission to access this endpoint.");
    }
    
    try {
      const result = await db.query(`
        SELECT 
          p.id AS payment_id,
          u.email,
          p.phone,
          TO_CHAR(p.submitted_at, 'DD/MM/YY') AS date,
          p.reference,
          p.proof_path,
          p.verified,
          p.status,
          SUM(c.price) AS total_price,
          JSON_AGG(
            JSON_BUILD_OBJECT('name', cake_counts.name, 'quantity', cake_counts.quantity)
          ) AS order_list
        FROM payments p
        JOIN users u ON p.user_id = u.id
        JOIN (
          SELECT 
            o.users_id,
            c.name,
            COUNT(c.id) AS quantity,
            MIN(c.price) AS price
          FROM orders o
          JOIN cakes c ON o.cakes_id = c.id
          GROUP BY o.users_id, c.name
        ) AS cake_counts ON cake_counts.users_id = u.id
        JOIN cakes c ON c.name = cake_counts.name
        GROUP BY p.id, u.email, p.phone, p.reference, p.proof_path, p.verified, p.status, p.submitted_at
        ORDER BY p.id DESC;
      `);

      res.render("admin.ejs", { payments: result.rows });
    } catch (err) {
      res.status(500).send("Error loading admin dashboard.");
    }
  });

  async function sendStatusEmail(to, reference, status) {
    let subject, html;

    if (status === "Verified") {
      subject = "✅ Your Cake Payment Has Been Verified!";
      html = `
        <h2>Payment Verified</h2>
        <p>Hi there,</p>
        <p>Your payment for order <b>${reference}</b> has been <b>successfully verified</b>.</p>
        <p>We’re now preparing your cake — you’ll get another update once it’s ready. 🎂</p>
        <p>Thank you for shopping with <b>Elysian Bytes</b>!</p>
      `;
    } else if (status === "Finished") {
      subject = "🎂 Your Cake Order is Finished!";
      html = `
        <h2>Good news!</h2>
        <p>Your cake order <b>${reference}</b> has been marked as <b>Finished</b>.</p>
        <p>It’s now ready for pickup. 🧁</p>
        <p>Please inform this number <b>09922075335</b></p>
        <p>If you are at the location : 2FCW+4X9, Rasay St, Toril, Davao City, 8000 Davao del Sur</p>
        <p>Thank you for choosing <b>Elysian Bytes</b>!</p>
      `;
    } else if (status === "Delivered") {
      subject = "🚚 Your Cake Order Has Been Delivered!";
      html = `
        <h2>Yay! 🎉</h2>
        <p>Your cake order <b>${reference}</b> has been <b>Delivered</b>.</p>
        <p>We hope you enjoy your sweet treat. 🍰</p>
        <p>Thank you for trusting <b>Elysian Bytes</b>!</p>
      `;
    }

    await transporter.sendMail({
      from: `"Elysian Bytes" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });
  }

  app.post("/admin/verify/:id", async (req, res) => {
    const { id } = req.params;

    try {
      await db.query("UPDATE payments SET verified = TRUE WHERE id = $1", [id]);

      const result = await db.query(
        `SELECT u.email, p.reference 
        FROM payments p 
        JOIN users u ON p.user_id = u.id 
        WHERE p.id = $1`,
        [id]
      );

      if (result.rows.length > 0) {
        const { email, reference } = result.rows[0];
        await sendStatusEmail(email, reference, "Verified");
      }

      res.redirect("/admin");
    } catch (err) {
      res.status(500).send("Error verifying payment.");
    }
  });

  app.post("/admin/finish/:id", async (req, res) => {
    const { id } = req.params;

    try {
      await db.query("UPDATE payments SET status = 'Finished' WHERE id = $1", [id]);

      const result = await db.query(
        `SELECT u.email, p.reference 
        FROM payments p 
        JOIN users u ON p.user_id = u.id 
        WHERE p.id = $1`,
        [id]
      );

      if (result.rows.length > 0) {
        const { email, reference } = result.rows[0];
        await sendStatusEmail(email, reference, "Finished");
      }

      res.redirect("/admin");
    } catch (err) {
      res.status(500).send("Error marking as Finished.");
    }
  });

  app.post("/admin/deliver/:id", async (req, res) => {
    const { id } = req.params;

    try {
      await db.query("UPDATE payments SET status = 'Delivered' WHERE id = $1", [id]);

      const result = await db.query(
        `SELECT u.email, p.reference 
        FROM payments p 
        JOIN users u ON p.user_id = u.id 
        WHERE p.id = $1`,
        [id]
      );

      if (result.rows.length > 0) {
        const { email, reference } = result.rows[0];
        await sendStatusEmail(email, reference, "Delivered");
      }

      res.redirect("/admin");
    } catch (err) {
      res.status(500).send("Error marking as Delivered.");
    }
  });

  app.post("/admin/delete/:id", async (req, res) => {
    const { id } = req.params;
    await db.query("DELETE FROM payments WHERE id = $1", [id]);
    res.redirect("/admin");
  });


  app.post("/like/:cakeId", async (req, res) => {
    

    try {

      if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, message: "Please log in first." });
      }

      const userId = req.user.id;
      const cakeId = parseInt(req.params.cakeId);

      const checkLike = await db.query(
        "SELECT * FROM likes WHERE user_id = $1 AND cake_id = $2",
        [userId, cakeId]
      );

      if (checkLike.rows.length > 0) {
        await db.query("DELETE FROM likes WHERE user_id = $1 AND cake_id = $2", [userId, cakeId]);
        await db.query("UPDATE cakes SET likes = likes - 1 WHERE id = $1", [cakeId]);
        await cakeDisplay();
        const result = items.filter(item => item.id === 1);
        return res.json({ success: true, liked: false });
      } else {
        await db.query("INSERT INTO likes (user_id, cake_id) VALUES ($1, $2)", [userId, cakeId]);
        await db.query("UPDATE cakes SET likes = likes + 1 WHERE id = $1", [cakeId]);
        await cakeDisplay();
        const result = items.filter(item => item.id === 1);
        return res.json({ success: true, liked: true });
      }

    } catch (err) {
      res.status(500).json({ success: false, message: "Server error" });
    }
  });


  const adminstorage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, "public/images/new/");
    },
    filename: (req, file, cb) => {
      const uniqueName = Date.now() + path.extname(file.originalname);
      cb(null, uniqueName);
    },
  });

  const adminupload = multer({ storage: adminstorage }); // ✅ FIXED


  app.get("/add-cake", (req, res) => {
    res.render("add-cake.ejs");
  });

  app.post("/add-cake", adminupload.single("img"), async (req, res) => {
    try {
      const { name, price } = req.body;
      const img = req.file ? `/images/new/${req.file.filename}` : null;

      if (!name || !price || !img) {
        return res.status(400).send("All fields are required.");
      }

      await db.query(
        "INSERT INTO cakes (name, img, price) VALUES ($1, $2, $3)",
        [name, req.file.filename, price]
      );

      res.redirect("/admin#manage-cakes");
    } catch (err) {
      res.status(500).send("Server error");
    }
  });

  app.get("/manage-cakes", async (req, res) => {
    const result = await db.query("SELECT * FROM cakes ORDER BY id DESC");
    res.render("partials/manage-cakes.ejs", { cakes: result.rows });
  });


  app.post("/update-cake/:id", adminupload.single("img"), async (req, res) => {
    const { id } = req.params;
    const { name, price } = req.body;
    let query, values;

    if (req.file) {
      const img = `/images/new/${req.file.filename}`;
      query = "UPDATE cakes SET name=$1, price=$2, img=$3 WHERE id=$4";
      values = [name, price, req.file.filename, id];
    } else {
      query = "UPDATE cakes SET name=$1, price=$2 WHERE id=$3";
      values = [name, price, id];
    }

    await db.query(query, values);
    res.redirect("/admin#manage-cakes");
  });

  app.post("/delete-cake/:id", async (req, res) => {
    const { id } = req.params;
    await db.query("DELETE FROM cakes WHERE id=$1", [id]);
    res.redirect("/admin#manage-cakes");
  });

  app.listen(port, () => {
      console.log("listening on port " + port);
  })



