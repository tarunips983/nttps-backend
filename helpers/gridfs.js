import { Readable } from "stream";
import { ObjectId } from "mongodb";
import { getBucket } from "../mongodb.js";

export async function uploadBuffer(file){

    const bucket=getBucket();

    return new Promise((resolve,reject)=>{

        const uploadStream=bucket.openUploadStream(file.originalname,{
            contentType:file.mimetype
        });

        Readable.from(file.buffer)
            .pipe(uploadStream)
            .on("error",reject)
            .on("finish",()=>{

                resolve(uploadStream.id.toString());

            });

    });

}

export async function deleteFile(id){

    const bucket=getBucket();

    await bucket.delete(new ObjectId(id));

}
