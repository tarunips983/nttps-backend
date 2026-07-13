import { MongoClient, GridFSBucket } from "mongodb";

const uri = process.env.MONGO_URI;

if (!uri) {
  throw new Error("Missing MONGO_URI environment variable");
}

const client = new MongoClient(uri);

let db;
let bucket;

export async function connectMongo() {
  if (db && bucket) {
    return { db, bucket };
  }

  await client.connect();

  db = client.db("tmcam");

  bucket = new GridFSBucket(db, {
    bucketName: "files"
  });

  console.log("✅ MongoDB Connected");

  return { db, bucket };
}

export { db, bucket };
