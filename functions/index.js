const createError = require("http-errors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const socket_io = require("socket.io");
const jwt = require("jsonwebtoken");
const path = require("path");
const logger = require("morgan");
const mongoose = require("mongoose");
const fs = require("fs");
require("dotenv").config({ path: "variables.env" });
const functions = require("firebase-functions");
const cors = require('cors')({
  origin: true,
});
//const cookieParser = require('cookie-parser')();

mongoose.connect("mongodb+srv://redsocial:redsocial123456@redsocialviajes.wgxmo.mongodb.net/?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.Promise = global.Promise; // Tell Mongoose to use ES6 promises
mongoose.connection.on("error", (err) => {
  console.error(err.message);
});

mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);
mongoose.set("autoIndex", false);





let express = require('express');
let app = express();
const validateFirebaseIdToken = async (req, res, next) => {
  functions.logger.log('Check if request is authorized with Firebase ID token');

  if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
      !(req.cookies && req.cookies.__session)) {
    functions.logger.error(
      'No Firebase ID token was passed as a Bearer token in the Authorization header.',
      'Make sure you authorize your request by providing the following HTTP header:',
      'Authorization: Bearer <Firebase ID Token>',
      'or by passing a "__session" cookie.'
    );
    res.status(403).send('Unauthorized');
    return;
  }

  let idToken;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    functions.logger.log('Found "Authorization" header');
    // Read the ID Token from the Authorization header.
    idToken = req.headers.authorization.split('Bearer ')[1];
  } else if(req.cookies) {
    functions.logger.log('Found "__session" cookie');
    // Read the ID Token from cookie.
    idToken = req.cookies.__session;
  } else {
    // No cookie
    res.status(403).send('Unauthorized');
    return;
  }

  try {
    const decodedIdToken = await admin.auth().verifyIdToken(idToken);
    functions.logger.log('ID Token correctly decoded', decodedIdToken);
    req.user = decodedIdToken;
    next();
    return;
  } catch (error) {
    functions.logger.error('Error while verifying Firebase ID token:', error);
    res.status(403).send('Unauthorized');
    return;
  }
};

app.use(cors);
//app.use(cookieParser);
//app.use(validateFirebaseIdToken);
const io = socket_io();







require("./models/Post");
require("./models/User");
require("./models/Comment");
require("./models/CommentReply");
require("./models/CommentReplyLike");
require("./models/CommentLike");
require("./models/PostLike");
require("./models/Following");
require("./models/Followers");
require("./models/Notification");
require("./models/ChatRoom");
require("./models/Message");


const userController = require("./controllers/userController");
app.io = io;

app.set("socketio", io);

io.use((socket, next) => {
  if (socket.handshake.query && socket.handshake.query.token) {
    const token = socket.handshake.query.token.split(" ")[1];
    jwt.verify(token, process.env.JWT_KEY, (err, decoded) => {
      if (err) return next(new Error("Authentication error"));
      socket.userData = decoded;
      next();
    });
  } else {
    next(new Error("Authentication error"));
  }
}).on("connection", (socket) => {
  // Connection now authenticated to receive further events
  socket.join(socket.userData.userId);
  io.in(socket.userData.userId).clients((err, clients) => {
    userController.changeStatus(socket.userData.userId, clients, io);
    //console.log(clients);
  });
  socket.on("typing", (data) => {
    socket.to(data.userId).emit("typing", { roomId: data.roomId });
  });
  socket.on("stoppedTyping", (data) => {
    socket.to(data.userId).emit("stoppedTyping", { roomId: data.roomId });
  });
  socket.on("disconnect", () => {
    socket.leave(socket.userData.userId);
    io.in(socket.userData.userId).clients((err, clients) => {
      userController.changeStatus(socket.userData.userId, clients, io);
      //console.log(clients);
    });
  });
});



const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
});

const postsRouter = require("./routes/post");
const usersRouter = require("./routes/user");
const commentsRouter = require("./routes/comment");
const notificationRouter = require("./routes/notification");
const chatRouter = require("./routes/chat");

app.use(helmet());
if (process.env.NODE_ENV === "production") {
  app.use(limiter);
  app.use(
    logger("common", {
      stream: fs.createWriteStream("./access.log", { flags: "a" }),
    })
  );
} else {
  app.use(logger("dev"));
}



app.use(express.static("public"));
/*app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "public", "index.html"));
});*/

app.use(express.json());
app.use(express.urlencoded({ extended: false }));



app.use("/api/post/", postsRouter);
app.use("/api/user/", usersRouter);
app.use("/api/comment/", commentsRouter);
app.use("/api/notification/", notificationRouter);
app.use("/api/chat/", chatRouter);

app.get("/auth/reset/password/:jwt", function (req, res) {
  return res.status(404).json({ message: "go to port 3000" });
});

app.use((req, res, next) => {
  next(createError(404));
});

/*
app.get('/', (request, response)=>{
  response.send("The best app");
});*/


app.use((err, req, res, next) => {
  // set locals, only providing error in development
  // res.locals.message = err.message;
  // res.locals.error = process.env.NODE_ENV === "development" ? err : {};
  console.log(err);

  // render the error page
  res.status(err.status || 500);
  res.json({
    error: {
      message: err.message,
    },
  });
});


exports.app = functions.https.onRequest(app);

// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions
//
// exports.helloWorld = functions.https.onRequest((request, response) => {
//   functions.logger.info("Hello logs!", {structuredData: true});
//   response.send("Hello from Firebase!");
// });
