import { KMSStorage } from "@extrimian/kms-core";
import { writeFileSync, readFileSync, existsSync } from "fs";

export class FileStorage implements KMSStorage {

    async add(key: string, data: any): Promise<void> {
        const keys = this.getFileObject();
        keys.set(key, data);
        this.saveFileObject(keys);
    }

    async get(key: string): Promise<any> {
        console.log("Llamando al Get de FIleStorage");
        const keys = this.getFileObject();
        return keys.get(key);
    }

    async getAll(): Promise<Map<string, any>> {
        return this.getFileObject();
    }

    async update(key: string, data: any) {
        const keys = this.getFileObject();
        keys.set(key, data);
        this.saveFileObject(keys);
    }

    async remove(key: string) {
        const keys = this.getFileObject();
        keys.delete(key);
        this.saveFileObject(keys);
    }

    private getFileObject(): Map<string, any> {
        if (existsSync("secure-storage.json")) {
            return new Map(JSON.parse(readFileSync("secure-storage.json").toString()))
        }
        return new Map<string, any>();
    }

    private saveFileObject(obj: Map<string, any>) {
        writeFileSync("secure-storage.json", JSON.stringify(Array.from(obj.entries())));
    }

}