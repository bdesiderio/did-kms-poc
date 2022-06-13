"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseConverter = exports.Base = exports.VerificationMethodHelper = exports.VerificationMethodTypes = void 0;
const multibase_1 = __importDefault(require("multibase"));
const bs58_1 = __importDefault(require("bs58"));
const util_1 = require("util");
// import { VerificationMethod } from "did-resolver";
var VerificationMethodTypes;
(function (VerificationMethodTypes) {
    VerificationMethodTypes["Ed25519VerificationKey2018"] = "Ed25519VerificationKey2018";
    VerificationMethodTypes["EcdsaSecp256k1VerificationKey2019"] = "EcdsaSecp256k1VerificationKey2019";
    VerificationMethodTypes["X25519KeyAgreementKey2019"] = "X25519KeyAgreementKey2019";
    VerificationMethodTypes["JsonWebKey2020"] = "JsonWebKey2020";
    VerificationMethodTypes["GpgVerificationKey2020"] = "GpgVerificationKey2020";
    VerificationMethodTypes["Bls12381G1Key2020"] = "Bls12381G1Key2020";
})(VerificationMethodTypes = exports.VerificationMethodTypes || (exports.VerificationMethodTypes = {}));
class VerificationMethodHelper {
    static getVMValue(vm) {
        if (vm.publicKeyBase58 != null) {
            return vm.publicKeyBase58;
        }
        else if (vm.publicKeyHex != null) {
            return vm.publicKeyHex;
        }
        else if (vm.publicKeyGpg != null) {
            return vm.publicKeyGpg;
        }
    }
}
exports.VerificationMethodHelper = VerificationMethodHelper;
var Base;
(function (Base) {
    Base["Hex"] = "hex";
    Base["Base58"] = "base58";
    Base["Base64"] = "base64";
    Base["JWK"] = "jwk";
})(Base = exports.Base || (exports.Base = {}));
class BaseConverter {
    static convertVM(verificationMethod, toBase) {
        //////////////// Hex <-> JWK
        if (verificationMethod.publicKeyHex && toBase == Base.JWK)
            verificationMethod.publicKeyJwk =
                this.convert(verificationMethod.publicKeyHex, Base.Hex, Base.JWK);
        if (verificationMethod.publicKeyJwk && toBase == Base.Hex)
            verificationMethod.publicKeyHex =
                this.convert(verificationMethod.publicKeyJwk, Base.Hex, Base.JWK);
        /////////////////////////////// Base58 <-> JWK
        if (verificationMethod.publicKeyBase58 && toBase == Base.JWK)
            verificationMethod.publicKeyJwk =
                this.convert(verificationMethod.publicKeyBase58, Base.Base58, Base.JWK);
        if (verificationMethod.publicKeyJwk && toBase == Base.Base58)
            verificationMethod.publicKeyBase58 =
                this.convert(verificationMethod.publicKeyJwk, Base.JWK, Base.Base58);
        /////////////////////////////// Base58 <-> HEX
        if (verificationMethod.publicKeyBase58 && toBase == Base.Hex)
            verificationMethod.publicKeyHex =
                this.convert(verificationMethod.publicKeyBase58, Base.Base58, Base.Hex);
        if (verificationMethod.publicKeyHex && toBase == Base.Base58)
            verificationMethod.publicKeyBase58 =
                this.convert(verificationMethod.publicKeyHex, Base.Hex, Base.Base58);
        return verificationMethod;
    }
    static convert(value, fromBase, toBase) {
        if (fromBase == Base.Base58 && toBase == Base.Hex) {
            return bs58_1.default.decode(value).toString("hex");
        }
        if (fromBase == Base.Hex && toBase == Base.Base58) {
            return bs58_1.default.encode(Buffer.from(value, "hex"));
        }
        if (fromBase == Base.Hex && toBase == Base.JWK) {
            return this.hexToJWK(value);
        }
        if (fromBase == Base.JWK && toBase == Base.Hex) {
            return this.JWKToHex(value);
        }
        if (fromBase == Base.Base58 && toBase == Base.JWK) {
            return this.hexToJWK(bs58_1.default.decode(value).toString("hex"));
        }
        if (fromBase == Base.JWK && toBase == Base.Base58) {
            return bs58_1.default.encode(Buffer.from(this.JWKToHex(value), "hex"));
        }
    }
    static hexToJWK(value) {
        value = value.replace("0x", "");
        // if (value.indexOf("04") == 0) {
        //     value = value.substring(2);
        // }
        return {
            // kid: "",
            kty: "EC",
            crv: "secp256k1",
            x: this.base64url(Buffer.from(value.substring(0, value.length / 2), "hex")),
            y: this.base64url(Buffer.from(value.substring(value.length / 2), "hex")),
        };
    }
    static base64url(buffer) {
        const decoder = new util_1.TextDecoder();
        const bytes = multibase_1.default.encode("base64url", buffer);
        return decoder.decode(bytes).slice(1);
    }
    static JWKToHex(value) {
        const b1 = Buffer.from(value.x, "base64url");
        const b2 = Buffer.from(value.y, "base64url");
        ;
        // return `0x04${b1.toString("hex")}${b2.toString("hex")}`;
        return `0x${b1.toString("hex")}${b2.toString("hex")}`;
    }
}
exports.BaseConverter = BaseConverter;
