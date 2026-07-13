import { MongoClient, GridFSBucket } from "mongodb";

const uri = process.env.MONGO_URI;

const client = new MongoClient(uri);

let db;
let bucket;

export async function connectMongo() {
    if (db) return;

    await client.connect();

    db = client.db("tmcam");

    bucket = new GridFSBucket(db,{
        bucketName:"files"
    });

    console.log("✅ MongoDB Connected");
}

export function getDB(){
    return db;
}

export function getBucket(){
    return bucket;
}
