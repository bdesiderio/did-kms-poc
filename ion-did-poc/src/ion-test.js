"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ion_sdk_1 = require("@decentralized-identity/ion-sdk");
const util_1 = require("util");
const multibase = require("multibase");
const node_fetch_1 = __importDefault(require("node-fetch"));
const kms_client_1 = require("@extrimian/kms-client");
const kms_core_1 = require("@extrimian/kms-core");
const jose = require("jose");
const ethers = require("ethers");
const kms_core_2 = require("@extrimian/kms-core");
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
function base64url(buffer) {
    const decoder = new util_1.TextDecoder();
    const bytes = multibase.encode("base64url", buffer);
    return decoder.decode(bytes).slice(1);
}
function hexToJWK(value) {
    return __awaiter(this, void 0, void 0, function* () {
        value = value.replace("0x", "");
        // if (value.indexOf("04") == 0) {
        //     value = value.substring(2);
        // }
        return {
            kty: "EC",
            crv: "secp256k1",
            x: base64url(Buffer.from(value.substring(0, value.length / 2), "hex")),
            y: base64url(Buffer.from(value.substring(value.length / 2), "hex")),
        };
    });
}
function JWKToHex(value) {
    return __awaiter(this, void 0, void 0, function* () {
        const b1 = Buffer.from(value.x, "base64");
        const b2 = Buffer.from(value.y, "base64");
        ;
        return `${b1.toString("hex")}${b2.toString("hex")}`;
    });
}
const signWithJWK = () => __awaiter(void 0, void 0, void 0, function* () {
    let mapping = new Map();
    let storage = {
        add: (key, data) => __awaiter(void 0, void 0, void 0, function* () { mapping.set(key, data); }),
        get: (key) => mapping.get(key),
        getAll: () => __awaiter(void 0, void 0, void 0, function* () { return mapping; }),
        remove: (key) => mapping.delete(key),
        update: (key, data) => mapping.set(key, data),
    };
    storage.add("0xf9fa7b7954357c4c08120043a236974200f742c75940b2efdc689fb52327f73b47b8e86b136ad69169ff580ddbe1f5214fd6e840fb9dc6588aa4feaa2752fa73", {
        curve: 'secp256k1',
        mnemonic: 'baile anemia término tabla tonto vivero remar gota útil morsa pájaro folio',
        privateKey: '0xe38a6a0195172c61c1b5d3429b6cb75a8abe141c021727c94f755c0d630e55d8',
        publicKey: '0x04f9fa7b7954357c4c08120043a236974200f742c75940b2efdc689fb52327f73b47b8e86b136ad69169ff580ddbe1f5214fd6e840fb9dc6588aa4feaa2752fa73',
        suite: kms_core_1.Suite.ES256k
    });
    let kms = new kms_client_1.KMSClient({
        lang: kms_core_1.LANG.es,
        storage: storage,
    });
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];
    const services = require('./keys/service1.json');
    const document = {
        publicKeys: publicKeys,
        services: services,
    };
    const updateKey = (yield kms.getPublicKeysBySuiteType(kms_core_1.Suite.ES256k))[0];
    const input = {
        didSuffix: "EiASij3K2GG4Exwrk4wlL-QZ01_OHV8dTfkXu4UZdykOaA",
        updatePublicKey: updateKey,
        nextUpdatePublicKey: updateKey,
        signer: {
            sign: (header, content) => __awaiter(void 0, void 0, void 0, function* () {
                return kms.sign(kms_core_1.Suite.ES256k, updateKey, content);
            })
        },
        servicesToAdd: services,
        idsOfServicesToRemove: ['service5Id'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['publicKeyModel2Id']
    };
    const result = yield ion_sdk_1.IonRequest.createUpdateRequest(input);
    const input2 = {
        didSuffix: "EiASij3K2GG4Exwrk4wlL-QZ01_OHV8dTfkXu4UZdykOaA",
        updatePublicKey: updateKey,
        nextUpdatePublicKey: updateKey,
        signer: ion_sdk_1.LocalSigner.create(kms_core_2.BaseConverter.getPrivateJWKfromHex("0xe38a6a0195172c61c1b5d3429b6cb75a8abe141c021727c94f755c0d630e55d8", "0x04f9fa7b7954357c4c08120043a236974200f742c75940b2efdc689fb52327f73b47b8e86b136ad69169ff580ddbe1f5214fd6e840fb9dc6588aa4feaa2752fa73")),
        servicesToAdd: services,
        idsOfServicesToRemove: ['service5Id'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['publicKeyModel2Id']
    };
    const result2 = yield ion_sdk_1.IonRequest.createUpdateRequest(input);
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };
    let ionCoreEndpoint = "http://20.237.2.83/create";
    let response = yield node_fetch_1.default(`${ionCoreEndpoint}`, options);
    if (response.status != 200 && response.status != 201) {
        const msg = yield response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    console.log(JSON.stringify(result));
});
const createKey = () => __awaiter(void 0, void 0, void 0, function* () {
    //KMS
    let mapping = new Map();
    let storage = {
        add: (key, data) => __awaiter(void 0, void 0, void 0, function* () { mapping.set(key, data); }),
        get: (key) => mapping.get(key),
        getAll: () => __awaiter(void 0, void 0, void 0, function* () { return mapping; }),
        remove: (key) => mapping.delete(key),
        update: (key, data) => mapping.set(key, data),
    };
    let kms = new kms_client_1.KMSClient({
        lang: kms_core_1.LANG.es,
        storage: storage,
    });
    const publicKey = yield kms.create(kms_core_1.Suite.ES256k);
    const secret = yield kms.export(publicKey.publicKeyJWK);
    const document = {
        publicKeys: [],
        services: [],
    };
    const recoveryKey = publicKey.publicKeyJWK;
    const updateKey = publicKey.publicKeyJWK;
    //LONG DID
    const longDid = ion_sdk_1.IonDid.createLongFormDid({
        document: document,
        recoveryKey: recoveryKey,
        updateKey: updateKey,
    });
    //Publicacion de un DID
    const input = { recoveryKey, updateKey, document };
    const result = ion_sdk_1.IonRequest.createCreateRequest(input);
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };
    let ionCoreEndpoint = "http://20.237.2.83/create";
    let response = yield node_fetch_1.default(`${ionCoreEndpoint}`, options);
    if (response.status != 200 && response.status != 201) {
        const msg = yield response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (yield response.json()).didDocumentMetadata.canonicalId;
    console.log(canonicalId);
});
const create2Key = () => __awaiter(void 0, void 0, void 0, function* () {
    const recoveryKey = require('./keys/jwkEs256k2Public.json');
    const updateKey = require('./keys/jwkEs256k2Public.json');
    const updateKey2 = require('./keys/jwkEs256k3Public.json');
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];
    const services = require('./keys/service1.json');
    // const services = [service];
    const document = {
        publicKeys,
        services
    };
    const input = { recoveryKey, updateKey: updateKey, document };
    const result = ion_sdk_1.IonRequest.createCreateRequest(input);
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };
    let ionCoreEndpoint = "http://localhost:3000/create";
    let response = yield node_fetch_1.default(`${ionCoreEndpoint}`, options);
    if (response.status != 200 && response.status != 201) {
        const msg = yield response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (yield response.json()).didDocumentMetadata.canonicalId;
    console.log(JSON.stringify(result));
    console.log(canonicalId);
});
const updateKey = (did) => __awaiter(void 0, void 0, void 0, function* () {
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];
    const updateKey = require('./keys/jwkEs256k2Public.json');
    const updateKey2 = require('./keys/jwkEs256k3Public.json');
    const services = require('./keys/service1.json');
    const input = {
        didSuffix: did,
        updatePublicKey: require('./keys/jwkEs256k1Public.json'),
        nextUpdatePublicKey: updateKey,
        signer: ion_sdk_1.LocalSigner.create(require('./keys/jwkEs256k1Private.json')),
        servicesToAdd: services,
        idsOfServicesToRemove: ['service5Id'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['publicKeyModel2Id']
    };
    const result = yield ion_sdk_1.IonRequest.createUpdateRequest(input);
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };
    let ionCoreEndpoint = "http://localhost:3000/create";
    let response = yield node_fetch_1.default(`${ionCoreEndpoint}`, options);
    if (response.status != 200 && response.status != 201) {
        const msg = yield response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    console.log(JSON.stringify(result));
    // const body = await response.json();
    // return body.didDocumentMetadata.canonicalId;
});
const recoveryKey = () => __awaiter(void 0, void 0, void 0, function* () {
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];
    const services = require('./keys/service1.json');
    const document = {
        publicKeys,
        services
    };
    const result = yield ion_sdk_1.IonRequest.createRecoverRequest({
        didSuffix: 'EiBDvFE0jvl4TvGCAIM3IF-9plhcvND3iD1qxprRTlYh5A',
        recoveryPublicKey: require('./keys/jwkEs256k1Public.json'),
        nextRecoveryPublicKey: require('./keys/jwkEs256k2Public.json'),
        nextUpdatePublicKey: require('./keys/jwkEs256k3Public.json'),
        document,
        signer: ion_sdk_1.LocalSigner.create(require('./keys/jwkEs256k1Private.json'))
    });
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };
    let ionCoreEndpoint = "http://localhost:3000";
    let response = yield node_fetch_1.default(`${ionCoreEndpoint}`, options);
    if (response.status != 200 && response.status != 201) {
        const msg = yield response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    return (yield response.json()).didDocumentMetadata.canonicalId;
});
signWithJWK();
// createKey();
// create2Key();
// updateKey("EiC1NF9qKDba1deg0MTEvioAOrqIbLgeBah4CemU4Qarzw"); 
