const express = require("express");
const router = express.Router();
const postController = require("../controllers/postController");
const userController = require("../controllers/userController");
const checkAuth = require("../middleware/checkAuth");
const postValidator = require("../middleware/schemaValidators/postValidator");
var bodyParser = require('body-parser')
router.post(
  "/getPosts",
  checkAuth,
  postValidator.getPosts,
  userController.getFollowings,
  postController.getPosts
);

router.post(
  "/getPostsByHashtag",
  checkAuth,
  postValidator.getPostsByHashtag,
  postController.getPostsByHashtag
);

router.post(
  "/getPostLikes",
  checkAuth,
  postValidator.getPostLikes,
  postController.getPostLikes
);
var urlencodedParser = bodyParser.urlencoded({ extended: false })
var jsonParser = bodyParser.json()
router.post(
  "/getPostsByLocation",

  checkAuth,
  postValidator.getPostsByLocation,
  postController.getPostsByLocation
);

router.post(
  "/addPost",
  checkAuth,
  postValidator.createPost,
  //postController.upload,
  postController.createPost
);

const upload = require("../models/ImageUpload");
const singleUpload = upload.single("image");

const aws = require("aws-sdk");
const multer = require("multer");
const multerS3 = require("multer-s3");



aws.config.update({
  secretAccessKey: 'n6oZresFJD/haOroXkjqcKuxw0HE6Dp9VUl3DO/Z',
  accessKeyId: 'AKIARMNPZ3AYQATX3XOI',
  region: "us-east-1"
});

const s3 = new aws.S3();

router.post("/subir", function (req, res) {
  const uid = req.params.id;
  console.log(req.file)
  singleUpload(req, res, function (err) {
    //console.log(req.file)
    if (err) {
      return res.json({
        success: false,
        errors: {
          title: "Image Upload Error",
          detail: err.message,
          error: err,
        },
      });
    }

    let update = { profilePicture: req.file.location };
    console.log(update)
/*
    User.findByIdAndUpdate(uid, update, { new: true })
      .then((user) => res.status(200).json({ success: true, user: user }))
      .catch((err) => res.status(400).json({ success: false, error: err }));*/
  });
});


router.post("/uploadPost", function (req, res) {
  console.log(req)
  const busboye = new Busboy({headers: req.headers})

  busboye.on("photo", async (fiedname, file, filename, encoding, mimetype) => {
    const params = {
      Bucket: "redsocialviajes",
      Key : filename,
      Body : file
    };

  const upload = await s3.upload(params).promise();
  console.log("uppl", upload);
 // museUploadQueue.add(upload)
  
  });
  return req.pipe(busboye);

  
 // const uid = req.params.id;

/*
  s3.putObject({
    Bucket: "redsocialviajes",
    Key: 'your-key-name.jpg', 
    Body: req.busboy,
    ACL: 'public-read', // your permisions  
  }, (err) => { 
    if (err) return res.status(400).send(err);
    res.send('File uploaded to S3');
})*/
/*
  singleUpload(req, res, function (err) {
    if (err) {
      return res.json({
        success: false,
        errors: {
          title: "Image Upload Error",
          detail: err.message,
          error: err,
        },
      });
    }
    console.log(req)
    let update = { profilePicture: req.file.location };
    console.log(update)

  });*/

      /*
    User.findByIdAndUpdate(uid, update, { new: true })
      .then((user) => res.status(200).json({ success: true, user: user }))
      .catch((err) => res.status(400).json({ success: false, error: err }));*/
});
/*
museUploadQueue.process(5, async (job,done) => {
  try{
    s3.getObject(
      {
      Bucket: "redsocialviajes",
      Key: job.data.Key, 
      },
    async (err,data) => {
      console.log("err",err)
      console.log("data", data)
      console.log("proc file", job.data);

      const formData = new FormData();
      formData.append("phpto", data.Body, job.data.Key);
      const uploadResults = await axios ({
        method: 'POST',
        url: uploadUrl,
        data: formData,
        headers: {
          Key,
          ...formData.getHeaders()
        }
      });
      console.log("hecho")
      done();
    });
  }catch(err){
      console.log(err)
  }

})*/

router.post(
  "/getPost",
  checkAuth,
  postValidator.getPost,
  postController.getPost
);

router.post(
  "/likePost/",
  checkAuth,
  postValidator.likePost,
  postController.likePost
);

router.post(
  "/delete/",
  checkAuth,
  postValidator.deletePost,
  postController.deletePost
);

module.exports = router;
