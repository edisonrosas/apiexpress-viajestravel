const Joi = require("@hapi/joi");
Joi.objectId = require("joi-objectid")(Joi);
const formidable = require('express-formidable');
const busboy = require('connect-busboy');
const fs = require('fs');
const AWS = require('aws-sdk');
const uuid = require('uuid')

exports.getPosts = (req, res, next) => {
  const schema = Joi.object({
    initialFetch: Joi.boolean().required(),
    lastId: Joi.when("initialFetch", {
      is: false,
      then: Joi.objectId().required(),
      otherwise: Joi.forbidden()
    })
  });
  console.log(req.body)
  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.getPostLikes = (req, res, next) => {
  const schema = Joi.object({
    postId: Joi.objectId().required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.getPostsByHashtag = (req, res, next) => {
  const schema = Joi.object({
    initialFetch: Joi.boolean().required(),
    hashtag: Joi.string()
      .min(1)
      .required(),
    lastId: Joi.when("initialFetch", {
      is: false,
      then: Joi.objectId().required(),
      otherwise: Joi.forbidden()
    })
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.getPostsByLocation = (req, res, next) => {
  const schema = Joi.object({
    initialFetch: Joi.boolean().required(),
    coordinates: Joi.string()
      .min(3)
      .required(),
    lastId: Joi.when("initialFetch", {
      is: false,
      then: Joi.objectId().required(),
      otherwise: Joi.forbidden()
    })
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.getPost = (req, res, next) => {
  const schema = Joi.object({
    postId: Joi.objectId().required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.likePost = (req, res, next) => {
  const schema = Joi.object({
    postId: Joi.objectId().required(),
    authorId: Joi.objectId().required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.deletePost = (req, res, next) => {
  const schema = Joi.object({
    postId: Joi.objectId().required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.message });
  }
  next();
};

exports.createPost = (req, res, next) => {
  console.log("req.body");
  //console.log(req.busboy.toJson())
  //console.log("esa")
  //console.log(JSON.stringify( req.body))
  //console.log(req.file)
  //console.log(req.body)
  //uploadFile(req.busboy)
  //console.log(JSON.stringify(req.body))
  //console.log(req)
 /* if (req.busboy) {
    req.busboy.on('file', (name, file, info) => {
      console.log(name)
      console.log(file)
      console.log(info)
    });
    req.busboy.on('field', (name, value, info) => {
      console.log(name)
      console.log(value)
      console.log(info)
    });
    req.pipe(req.busboy);
  }*/

 /* const form = formidable({ multiples: true });

  form.parse(req, (err, fields, files) => {
    if (err) {
      next(err);
      return;
    }
    res.json({ fields, files });
  });

  console.log(form)*/
  var object = {};
  //req.body.forEach(function(value, key){
      //object[key] = value;
  //});
  //var json = JSON.stringify(object);
  //console.log(json)

  const validateObject = Object.assign({}, req.body);
  //console.log(validateObject)
  
  validateObject.tags = JSON.parse(validateObject.tags);
  //validateObject.tags = validateObject.tags;
  const schema = Joi.object({
    description: Joi.string()
      .allow("")
      .required(),
    tags: Joi.array().required(),
    coordinates: Joi.string()
      .allow("")
      .required(),
    locationName: Joi.string()
      .allow("")
      .required(),
    photo: Joi.string().required()
  });
  //console.log("obj",JSON.parse(validateObject))
  const { error, value } = schema.validate(validateObject);
  if (error) {
    console.log("error")
    console.log(error.message)
    return res.status(400).json({ message: error.message });
  }
  next(); 
};
const ID = 'AKIARMNPZ3AYQATX3XOI';
const SECRET = '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';

// The name of the bucket that you have created
const BUCKET_NAME = 'redsocialviajes';
const s3 = new AWS.S3({
  accessKeyId: ID,
  secretAccessKey: SECRET
});


const uploadFile = (fileName) => {
  // Read content from the file
  const fileContent = fs.readFileSync(fileName);

  // Setting up S3 upload parameters
  const params = {
      Bucket: BUCKET_NAME,
      Key: "post"+uuid(), // File name you want to save as in S3
      Body: fileContent
  };

  // Uploading files to the bucket
  s3.upload(params, function(err, data) {
      if (err) {
          throw err;
      }
      console.log(`File uploaded successfully. ${data.Location}`);
  });
};