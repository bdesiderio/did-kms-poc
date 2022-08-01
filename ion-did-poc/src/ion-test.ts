import { IonDid, IonDocumentModel, IonRequest, IonPublicKeyPurpose } from "@decentralized-identity/ion-sdk";
import fetch from "node-fetch";
import { KMSClient } from "@extrimian/kms-client";
import { LANG, Suite } from "@extrimian/kms-core";
import { FileStorage } from "./file-storage";

let _kms: KMSClient = null;
let storage = new FileStorage();

const getKMS = async (): Promise<KMSClient> => {


    if (!_kms) {
        _kms = new KMSClient({
            lang: LANG.es,
            storage: storage,
        });
    }

    return _kms;
}

const createKey = async () => {
    let kms = await getKMS();

    const publicKey1 = await kms.create(Suite.ES256k);
    const secret1 = await kms.export(publicKey1.publicKeyJWK);
    console.log(secret1);

    const publicKey2 = await kms.create(Suite.ES256k);
    const secret2 = await kms.export(publicKey2.publicKeyJWK);
    console.log(secret2);

    //CREATE BBS PUBLIC KEYS
    const bbs = await kms.create(Suite.Bbsbls2020);
    const secretBbs = await kms.export(bbs.publicKeyJWK);
    console.log(secretBbs);

    const document: IonDocumentModel = {
        publicKeys: [{
            id: "bbs2020",
            publicKeyJwk: bbs.publicKeyJWK,
            type: "Bls12381G1Key2020",
            purposes: [IonPublicKeyPurpose.AssertionMethod],
        }],
        services: [],
    };

    const recoveryKey = publicKey1.publicKeyJWK;
    const updateKey = publicKey1.publicKeyJWK;

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

    let ionCoreEndpoint = "http://localhost:3000/create";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (await response.json() as any).didDocumentMetadata.canonicalId;

    console.log(canonicalId);
}

// const updateDID = async (did: string) => {
//     const publicKey = require('./keys/publicKeyModel1.json');
//     const publicKeys = [publicKey];

//     // let keys = Array.from((await storage.getAll()).values());
//     // keys = keys.filter(x => x.suite == "es256k");

//     let kms = await getKMS();

//     const updateKey = (await kms.getPublicKeysBySuiteType(Suite.ES256k))[0];

//     const nextUpdateKey1 = await kms.create(Suite.ES256k);
//     const nextUpdateKey2 = await kms.create(Suite.ES256k);

//     const services = require('./keys/service1.json');
//     const input = {
//         didSuffix: did,
//         updatePublicKey: updateKey,
//         nextUpdatePublicKey: [nextUpdateKey1.publicKeyJWK, nextUpdateKey2.publicKeyJWK],
//         signer: {
//             sign: async (header: object, content: object): Promise<string> => {
//                 return await kms.sign(Suite.ES256k, updateKey, content);
//             }
//         },
//         servicesToAdd: services,
//         idsOfServicesToRemove: ['service5Id'],
//         publicKeysToAdd: publicKeys,
//         idsOfPublicKeysToRemove: ['publicKeyModel333Id']
//     };

//     const result = await IonRequest.createUpdateRequest(input);

//     const options = {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(result)
//     };

//     let ionCoreEndpoint = "http://localhost:3000/create";

//     let response = await fetch(`${ionCoreEndpoint}`, options)
//     if (response.status != 200 && response.status != 201) {
//         // keys.forEach(key => {
//         //     storage.remove(key.)
//         // });
//         const msg = await response.json();
//         throw new Error(`Ion DID creation is not ok: ${msg}`);
//     }

//     console.log(JSON.stringify(result));
// }

// const DIDRecovery = async (did: string) => {
//     const publicKey = require('./keys/publicKeyModel1.json');
//     const publicKeys = [publicKey];

//     let kms = await getKMS();

//     const recoveryKey = (await kms.getPublicKeysBySuiteType(Suite.ES256k))[0];

//     const nextUpdateKey1 = await kms.create(Suite.ES256k);
//     const nextUpdateKey2 = await kms.create(Suite.ES256k);

//     const services = require('./keys/service1.json');

//     const document: IonDocumentModel = {
//         publicKeys,
//         services
//     };

//     const result = await IonRequest.createRecoverRequest({
//         didSuffix: did,
//         recoveryPublicKey: recoveryKey,
//         nextRecoveryPublicKey: nextUpdateKey1.publicKeyJWK,
//         nextUpdatePublicKey: nextUpdateKey1.publicKeyJWK,
//         document,
//         signer: {
//             sign: async (header: object, content: object): Promise<string> => {
//                 return await kms.sign(Suite.ES256k, recoveryKey, content);
//             }
//         },
//     });

//     const options = {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(result)
//     };

//     let ionCoreEndpoint = "http://localhost:3000/create";

//     let response = await fetch(`${ionCoreEndpoint}`, options)
//     if (response.status != 200 && response.status != 201) {
//         const msg = await response.json();
//         throw new Error(`Ion DID creation is not ok: ${msg}`);
//     }
//     return (await response.json() as any).didDocumentMetadata.canonicalId;
// }

// signWithJWK();
createKey();
// updateDID("EiA-JJD2cnYY4Gxm2ilLs2Q6Gid6QJqx7Ka_-GYEQrGAhA");
// DIDRecovery("EiCNjGeMUijrlXoriNBlzfbrYkdZxpBxc_q7N7RUS07Mpg");