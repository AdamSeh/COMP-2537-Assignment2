//connect .env file
const dotenv = require('dotenv');
dotenv.config();

//mongodb import
const MongoClient = require('mongodb').MongoClient;

//link variables with env file
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

//build connection string then make new client
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
var database = new MongoClient(atlasURI);

module.exports = {database};