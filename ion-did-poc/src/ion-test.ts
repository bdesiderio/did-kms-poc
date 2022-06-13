import { IonDid, IonKey, IonDocumentModel, IonPublicKeyPurpose, JwkEs256k, LocalSigner, IonPublicKeyModel, IonServiceModel, IonRequest, IonSdkConfig, IonNetwork } from "@decentralized-identity/ion-sdk";
import { TextDecoder } from "util";
const multibase = require("multibase");
import fetch from "node-fetch";
import { KMSClient } from "@extrimian/kms-client";
import { LANG, Suite } from "@extrimian/kms-core";
const jose = require("jose");
const ethers = require("ethers");
import { BaseConverter, Base } from "@extrimian/kms-core";
// import { } from "./"
// import fetch from "node-fetch";

function hex2base64url(dataHex) {
    const buffer = Buffer.from(dataHex, "hex");
    const base64 = buffer.toString("base64");
    const base64url = base64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
    return base64url;
}

function getJWKfromHex(_privKey) {
    let privKey = _privKey;

    const s = new ethers.utils.SigningKey(privKey);
    let pubKey = s.publicKey;

    // remove 0x and 0x04 to be used in jose library
    privKey = privKey.replace("0x", "");
    pubKey = pubKey.replace("0x04", "");

    return {
        crv: "secp256k1",
        kty: "EC",
        d: hex2base64url(privKey),
        x: hex2base64url(pubKey.substr(0, 64)),
        y: hex2base64url(pubKey.substr(64, 64))
    };
}

function base64url(buffer: Uint8Array) {
    const decoder = new TextDecoder();
    const bytes = multibase.encode("base64url", buffer);
    return decoder.decode(bytes).slice(1);
}

async function hexToJWK(value: string) {
    value = value.replace("0x", "");

    // if (value.indexOf("04") == 0) {
    //     value = value.substring(2);
    // }

    return {
        kty: "EC",
        crv: "secp256k1",
        x: base64url(Buffer.from(value.substring(0, value.length / 2), "hex")),
        y: base64url(Buffer.from(value.substring(value.length / 2), "hex")),
    }
}

async function JWKToHex(value: { kty: string, crv: string, x: string, y: string }) {
    const b1 = Buffer.from(value.x, "base64");
    const b2 = Buffer.from(value.y, "base64");;

    return `${b1.toString("hex")}${b2.toString("hex")}`;
}

const signWithJWK = async () => {
    let mapping = new Map();

    let storage = {
        add: async (key, data) => { mapping.set(key, data) },
        get: (key) => mapping.get(key),
        getAll: async () => mapping,
        remove: (key) => mapping.delete(key),
        update: (key, data) => mapping.set(key, data),
    };

    storage.add("0xf18fbae4ad02b442d2a835653aba75457ba9c6f855d27f0851569eacbe946a3d875a6f3bdb8aecd5d7c259217481b1969c43801158f6701c543e7626dde4dc53", {
        curve: 'secp256k1',
        mnemonic: 'suave ebrio alcalde peluca asa croqueta fuerza ira golfo tela ruleta bello',
        privateKey: '0x7702c81599e1d17a7775eac6b653f4f7d0380420428f75b18e672dbf56cf8b47',
        publicKey: '0x04f18fbae4ad02b442d2a835653aba75457ba9c6f855d27f0851569eacbe946a3d875a6f3bdb8aecd5d7c259217481b1969c43801158f6701c543e7626dde4dc53',
        suite: Suite.ES256k
    });

    let kms = new KMSClient({
        lang: LANG.es,
        storage: storage,
    });

    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');

    const document: IonDocumentModel = {
        publicKeys: publicKeys,
        services: services,
    };

    const updateKey = (await kms.getPublicKeysBySuiteType(Suite.ES256k))[0];

    const input = {
        didSuffix: "EiAUUKVtk6AUjRKpveINSdq2CySrzP4ZOLsMfecv3MgixA",
        updatePublicKey: updateKey,
        nextUpdatePublicKey: updateKey,
        signer: {
            sign: async (header: object, content: object): Promise<string> => {
                return kms.sign(Suite.ES256k, updateKey, content);
            }
        },
        servicesToAdd: services,
        idsOfServicesToRemove: ['service5Id'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['publicKeyModel2Id']
    };

    const result = await IonRequest.createUpdateRequest(input);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://20.237.2.83/create";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }

    console.log(JSON.stringify(result));
}

const createKey = async () => {
    //KMS
    let mapping = new Map();

    let storage = {
        add: async (key, data) => { mapping.set(key, data) },
        get: (key) => mapping.get(key),
        getAll: async () => mapping,
        remove: (key) => mapping.delete(key),
        update: (key, data) => mapping.set(key, data),
    };

    let kms = new KMSClient({
        lang: LANG.es,
        storage: storage,
    });

    const publicKey = await kms.create(Suite.ES256k);

    const secret = await kms.export(publicKey.publicKeyJWK);

    const document: IonDocumentModel = {
        publicKeys: [],
        services: [],
    };

    const recoveryKey = publicKey.publicKeyJWK;
    const updateKey = publicKey.publicKeyJWK;

    //LONG DID
    const longDid = IonDid.createLongFormDid({
        document: document,
        recoveryKey: recoveryKey,
        updateKey: updateKey,
    });

    //Publicacion de un DID
    const input = { recoveryKey, updateKey, document };
    const result = IonRequest.createCreateRequest(input);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://20.237.2.83/create";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (await response.json() as any).didDocumentMetadata.canonicalId;

    console.log(canonicalId);
}

const create2Key = async () => {
    const recoveryKey = require('./keys/jwkEs256k2Public.json');
    const updateKey = require('./keys/jwkEs256k2Public.json');
    const updateKey2 = require('./keys/jwkEs256k3Public.json');
    const publicKey = require('./keys/publicKeyModel1.json');

    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');
    // const services = [service];

    const document: IonDocumentModel = {
        publicKeys,
        services
    };
    const input = { recoveryKey, updateKey: updateKey, document };
    const result = IonRequest.createCreateRequest(input);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://localhost:3000/create";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (await response.json() as any).didDocumentMetadata.canonicalId;

    console.log(JSON.stringify(result));
    console.log(canonicalId);
}

const updateKey = async (did: string) => {
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];

    const updateKey = require('./keys/jwkEs256k2Public.json');
    const updateKey2 = require('./keys/jwkEs256k3Public.json');

    const services = require('./keys/service1.json');
    const input = {
        didSuffix: did,
        updatePublicKey: require('./keys/jwkEs256k1Public.json'),
        nextUpdatePublicKey: updateKey,
        signer: LocalSigner.create(require('./keys/jwkEs256k1Private.json')),
        servicesToAdd: services,
        idsOfServicesToRemove: ['service5Id'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['publicKeyModel2Id']
    };

    const result = await IonRequest.createUpdateRequest(input);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://localhost:3000/create";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }

    console.log(JSON.stringify(result));
    // const body = await response.json();
    // return body.didDocumentMetadata.canonicalId;
}

const recoveryKey = async () => {
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');

    const document: IonDocumentModel = {
        publicKeys,
        services
    };

    const result = await IonRequest.createRecoverRequest({
        didSuffix: 'EiBDvFE0jvl4TvGCAIM3IF-9plhcvND3iD1qxprRTlYh5A',
        recoveryPublicKey: require('./keys/jwkEs256k1Public.json'),
        nextRecoveryPublicKey: require('./keys/jwkEs256k2Public.json'),
        nextUpdatePublicKey: require('./keys/jwkEs256k3Public.json'),
        document,
        signer: LocalSigner.create(require('./keys/jwkEs256k1Private.json'))
    });

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://localhost:3000";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    return (await response.json() as any).didDocumentMetadata.canonicalId;
}

signWithJWK();
// createKey();
// create2Key();
// updateKey("EiC1NF9qKDba1deg0MTEvioAOrqIbLgeBah4CemU4Qarzw"); 