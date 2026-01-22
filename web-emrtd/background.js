/**
 * MIT License
 * 
 * Copyright (c) 2020-2024 Estonian Information System Authority
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

(function () {
    'use strict';

    (function() {
        const env = {};
        try {
            if (process) {
                process.env = Object.assign({}, process.env);
                Object.assign(process.env, env);
                return;
            }
        } catch (e) {} // avoid ReferenceError: process is not defined
        globalThis.process = { env:env };
    })();

    var Action;
    (function (Action) {
        Action["WARNING"] = "web-emrtd:warning";
        Action["STATUS"] = "web-emrtd:status";
        Action["STATUS_ACK"] = "web-emrtd:status-ack";
        Action["STATUS_SUCCESS"] = "web-emrtd:status-success";
        Action["STATUS_FAILURE"] = "web-emrtd:status-failure";
        Action["AUTHENTICATE_WITH_EMRTD"] = "web-emrtd:authenticate";
        Action["AUTHENTICATE_WITH_EMRTD_ACK"] = "web-emrtd:authenticate-ack";
        Action["AUTHENTICATE_WITH_EMRTD_SUCCESS"] = "web-emrtd:authenticate-success";
        Action["AUTHENTICATE_WITH_EMRTD_FAILURE"] = "web-emrtd:authenticate-failure";
        Action["AUTHENTICATE_EMRTD_CA"] = "web-emrtd:authenticate_ca";
        Action["AUTHENTICATE_EMRTD_CA_ACK"] = "web-emrtd:authenticate_ca-ack";
        Action["AUTHENTICATE_EMRTD_CA_SUCCESS"] = "web-emrtd:authenticate_ca-success";
        Action["AUTHENTICATE_EMRTD_CA_FAILURE"] = "web-emrtd:authenticate_ca-failure";
    })(Action || (Action = {}));
    var Action$1 = Action;

    var libraryConfig = Object.freeze({
        VERSION: "2.0.2",
        EXTENSION_HANDSHAKE_TIMEOUT: 5000,
        NATIVE_APP_HANDSHAKE_TIMEOUT: 5 * 1000,
        DEFAULT_USER_INTERACTION_TIMEOUT: 2 * 60 * 1000,
        MAX_EXTENSION_LOAD_DELAY: 1000,
    });

    var ErrorCode;
    (function (ErrorCode) {
        ErrorCode["ERR_WEBEID_ACTION_TIMEOUT"] = "ERR_WEBEID_ACTION_TIMEOUT";
        ErrorCode["ERR_WEBEID_USER_TIMEOUT"] = "ERR_WEBEID_USER_TIMEOUT";
        ErrorCode["ERR_WEBEID_SERVER_TIMEOUT"] = "ERR_WEBEID_SERVER_TIMEOUT";
        ErrorCode["ERR_WEBEID_VERSION_MISMATCH"] = "ERR_WEBEID_VERSION_MISMATCH";
        ErrorCode["ERR_WEBEID_VERSION_INVALID"] = "ERR_WEBEID_VERSION_INVALID";
        ErrorCode["ERR_WEBEID_EXTENSION_UNAVAILABLE"] = "ERR_WEBEID_EXTENSION_UNAVAILABLE";
        ErrorCode["ERR_WEBEID_NATIVE_UNAVAILABLE"] = "ERR_WEBEID_NATIVE_UNAVAILABLE";
        ErrorCode["ERR_WEBEID_UNKNOWN_ERROR"] = "ERR_WEBEID_UNKNOWN_ERROR";
        ErrorCode["ERR_WEBEID_CONTEXT_INSECURE"] = "ERR_WEBEID_CONTEXT_INSECURE";
        ErrorCode["ERR_WEBEID_PROTOCOL_INSECURE"] = "ERR_WEBEID_PROTOCOL_INSECURE";
        ErrorCode["ERR_WEBEID_TLS_CONNECTION_BROKEN"] = "ERR_WEBEID_TLS_CONNECTION_BROKEN";
        ErrorCode["ERR_WEBEID_TLS_CONNECTION_INSECURE"] = "ERR_WEBEID_TLS_CONNECTION_INSECURE";
        ErrorCode["ERR_WEBEID_TLS_CONNECTION_WEAK"] = "ERR_WEBEID_TLS_CONNECTION_WEAK";
        ErrorCode["ERR_WEBEID_CERTIFICATE_CHANGED"] = "ERR_WEBEID_CERTIFICATE_CHANGED";
        ErrorCode["ERR_WEBEID_ORIGIN_MISMATCH"] = "ERR_WEBEID_ORIGIN_MISMATCH";
        ErrorCode["ERR_WEBEID_SERVER_REJECTED"] = "ERR_WEBEID_SERVER_REJECTED";
        ErrorCode["ERR_WEBEID_USER_CANCELLED"] = "ERR_WEBEID_USER_CANCELLED";
        ErrorCode["ERR_WEBEID_NATIVE_INVALID_ARGUMENT"] = "ERR_WEBEID_NATIVE_INVALID_ARGUMENT";
        ErrorCode["ERR_WEBEID_NATIVE_FATAL"] = "ERR_WEBEID_NATIVE_FATAL";
        ErrorCode["ERR_WEBEID_ACTION_PENDING"] = "ERR_WEBEID_ACTION_PENDING";
        ErrorCode["ERR_WEBEID_MISSING_PARAMETER"] = "ERR_WEBEID_MISSING_PARAMETER";
    })(ErrorCode || (ErrorCode = {}));
    var ErrorCode$1 = ErrorCode;

    class UserTimeoutError extends Error {
        constructor(message = "user failed to respond in time") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_USER_TIMEOUT;
        }
    }

    /**
     * Convert between byte array, Base64 and hexadecimal string formats.
     *
     * @example
     *  new ByteArray([ 72, 101, 108, 108, 111 ]).toBase64() // SGVsbG8=
     *  new ByteArray().fromHex("48656c6c6f").toBase64()     // SGVsbG8=
     *  new ByteArray().fromBase64("SGVsbG8=").toHex()       // 48656c6c6f
     *  new ByteArray().fromHex("48656c6c6f").valueOf()      // [72, 101, 108, 108, 111]
     */
    class ByteArray {
        get length() {
            return this.data.length;
        }
        constructor(byteArray) {
            this.data = byteArray || [];
        }
        fromBase64(base64) {
            this.data = atob(base64).split("").map(c => c.charCodeAt(0));
            return this;
        }
        toBase64() {
            return btoa(this.data.reduce((acc, curr) => acc += String.fromCharCode(curr), ""));
        }
        fromHex(hex) {
            const data = [];
            for (let i = 0; i < hex.length; i += 2) {
                data.push(parseInt(hex.substr(i, 2), 16));
            }
            this.data = data;
            return this;
        }
        toHex() {
            return this.data.map((byte) => ("0" + (byte & 0xFF).toString(16)).slice(-2)).join("");
        }
        valueOf() {
            return this.data;
        }
    }

    class NativeUnavailableError extends Error {
        constructor(message = "Web-eID eMRTD native application is not available") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_NATIVE_UNAVAILABLE;
        }
    }

    class UnknownError extends Error {
        constructor(message = "an unknown error occurred") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_UNKNOWN_ERROR;
        }
    }

    class ActionPendingError extends Error {
        constructor(message = "same action for Web eMRTD browser extension is already pending") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_ACTION_PENDING;
        }
    }

    class ActionTimeoutError extends Error {
        constructor(message = "extension message timeout") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_ACTION_TIMEOUT;
        }
    }

    const SECURE_CONTEXTS_INFO_URL = "https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts";
    class ContextInsecureError extends Error {
        constructor(message = "Secure context required, see " + SECURE_CONTEXTS_INFO_URL) {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_CONTEXT_INSECURE;
        }
    }

    class ExtensionUnavailableError extends Error {
        constructor(message = "Web eMRTD extension is not available") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_EXTENSION_UNAVAILABLE;
        }
    }

    class NativeFatalError extends Error {
        constructor(message = "native application terminated with a fatal error") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_NATIVE_FATAL;
        }
    }

    class NativeInvalidArgumentError extends Error {
        constructor(message = "native application received an invalid argument") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_NATIVE_INVALID_ARGUMENT;
        }
    }

    class UserCancelledError extends Error {
        constructor(message = "request was cancelled by the user") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_USER_CANCELLED;
        }
    }

    class VersionInvalidError extends Error {
        constructor(message = "invalid version string") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_VERSION_INVALID;
        }
    }

    function tmpl(strings, requiresUpdate) {
        return `Update required for Web-eID ${requiresUpdate}`;
    }
    class VersionMismatchError extends Error {
        constructor(message, versions, requiresUpdate) {
            if (!message) {
                if (!requiresUpdate) {
                    message = "requiresUpdate not provided";
                }
                else if (requiresUpdate.extension && requiresUpdate.nativeApp) {
                    message = tmpl `${"extension and native app"}`;
                }
                else if (requiresUpdate.extension) {
                    message = tmpl `${"extension"}`;
                }
                else if (requiresUpdate.nativeApp) {
                    message = tmpl `${"native app"}`;
                }
            }
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_VERSION_MISMATCH;
            this.requiresUpdate = requiresUpdate;
            if (versions) {
                const { library, extension, nativeApp } = versions;
                Object.assign(this, { library, extension, nativeApp });
            }
        }
    }

    const errorCodeToErrorClass = {
        [ErrorCode$1.ERR_WEBEID_ACTION_PENDING]: ActionPendingError,
        [ErrorCode$1.ERR_WEBEID_ACTION_TIMEOUT]: ActionTimeoutError,
        [ErrorCode$1.ERR_WEBEID_CONTEXT_INSECURE]: ContextInsecureError,
        [ErrorCode$1.ERR_WEBEID_EXTENSION_UNAVAILABLE]: ExtensionUnavailableError,
        [ErrorCode$1.ERR_WEBEID_NATIVE_INVALID_ARGUMENT]: NativeInvalidArgumentError,
        [ErrorCode$1.ERR_WEBEID_NATIVE_FATAL]: NativeFatalError,
        [ErrorCode$1.ERR_WEBEID_NATIVE_UNAVAILABLE]: NativeUnavailableError,
        [ErrorCode$1.ERR_WEBEID_USER_CANCELLED]: UserCancelledError,
        [ErrorCode$1.ERR_WEBEID_USER_TIMEOUT]: UserTimeoutError,
        [ErrorCode$1.ERR_WEBEID_VERSION_INVALID]: VersionInvalidError,
        [ErrorCode$1.ERR_WEBEID_VERSION_MISMATCH]: VersionMismatchError,
    };
    function serializeError(error) {
        const { message, name, fileName, lineNumber, columnNumber, stack, } = error;
        return {
            ...(Object.fromEntries(Object.getOwnPropertyNames(error)
                .map((prop) => [prop, error[prop]]))),
            message,
            name,
            fileName,
            lineNumber,
            columnNumber,
            stack,
        };
    }
    function deserializeError(errorObject) {
        let error;
        if (typeof errorObject.code == "string" && errorObject.code in errorCodeToErrorClass) {
            const CustomError = errorCodeToErrorClass[errorObject.code];
            error = new CustomError();
        }
        else {
            error = new UnknownError();
        }
        for (const [key, value] of Object.entries(errorObject)) {
            error[key] = value;
        }
        return error;
    }

    /**
     * Calculates the size of an object's JSON representation in bytes
     *
     * @param object Any JSON stringifyable object
     *
     * @returns Size in bytes
     */
    function calculateJsonSize(object) {
        const objectString = JSON.stringify(object);
        const objectStringBlob = new Blob([objectString]);
        return objectStringBlob.size;
    }

    var _a;
    var config = Object.freeze({
        NATIVE_APP_NAME: "eu.web.emrtd",
        VERSION: "1.0.0",
        NATIVE_MESSAGE_MAX_BYTES: 8192,
        NATIVE_GRACEFUL_DISCONNECT_TIMEOUT: 5000,
        TOKEN_SIGNING_BACKWARDS_COMPATIBILITY: ((_a = process.env.TOKEN_SIGNING_BACKWARDS_COMPATIBILITY) === null || _a === void 0 ? void 0 : _a.toUpperCase()) === "TRUE",
        TOKEN_SIGNING_USER_INTERACTION_TIMEOUT: 1000 * 60 * 5,
        DEBUG: true,
    });

    /**
     * Sleeps for a specified time before resolving the returned promise.
     *
     * @param milliseconds Time in milliseconds until the promise is resolved
     *
     * @returns Empty promise
     */
    function sleep(milliseconds) {
        return new Promise((resolve) => {
            setTimeout(() => resolve(), milliseconds);
        });
    }
    /**
     * Throws an error after a specified time has passed.
     *
     * Useful in combination with Promise.race(...)
     *
     * @param milliseconds Time in milliseconds until the promise is rejected
     * @param error Error object which will be used to reject the promise
     *
     * @example
     *   await Promise.race([
     *     doAsyncOperation(),
     *     throwAfterTimeout(3600, new TimeoutError()),
     *   ])
     */
    async function throwAfterTimeout(milliseconds, error) {
        await sleep(milliseconds);
        throw error;
    }

    var NativeAppState;
    (function (NativeAppState) {
        NativeAppState[NativeAppState["UNINITIALIZED"] = 0] = "UNINITIALIZED";
        NativeAppState[NativeAppState["CONNECTING"] = 1] = "CONNECTING";
        NativeAppState[NativeAppState["CONNECTED"] = 2] = "CONNECTED";
        NativeAppState[NativeAppState["DISCONNECTED"] = 3] = "DISCONNECTED";
    })(NativeAppState || (NativeAppState = {}));
    class NativeAppService {
        constructor() {
            this.state = NativeAppState.UNINITIALIZED;
            this.port = null;
            this.pending = null;
            this.activeConnection = null;
        }
        async connect() {
            var _a;
            this.state = NativeAppState.CONNECTING;
            this.port = browser.runtime.connectNative(config.NATIVE_APP_NAME);
            this.port.onDisconnect.addListener(this.disconnectListener.bind(this));
            try {
                const message = await this.nextMessage(libraryConfig.NATIVE_APP_HANDSHAKE_TIMEOUT);
                if (message.version) {
                    this.state = NativeAppState.CONNECTED;
                    new Promise((resolve, reject) => this.activeConnection = { resolve, reject });
                    return message;
                }
                if (message) {
                    throw new NativeUnavailableError(`expected native application to reply with a version, got ${JSON.stringify(message)}`);
                }
                else if (this.port.error) {
                    throw new NativeUnavailableError(this.port.error.message);
                }
                else {
                    throw new NativeUnavailableError("unexpected error");
                }
            }
            catch (error) {
                if (this.port.error) {
                    console.error(this.port.error);
                }
                if (error instanceof Error) {
                    throw error;
                }
                else if ((_a = this.port.error) === null || _a === void 0 ? void 0 : _a.message) {
                    throw new NativeUnavailableError(this.port.error.message);
                }
                else {
                    throw new NativeUnavailableError("unexpected error");
                }
            }
        }
        async disconnectListener() {
            var _a, _b, _c, _d;
            config.DEBUG && console.log("Native app disconnected");
            (_a = chrome === null || chrome === void 0 ? void 0 : chrome.runtime) === null || _a === void 0 ? void 0 : _a.lastError;
            await new Promise((resolve) => setTimeout(resolve));
            (_b = this.activeConnection) === null || _b === void 0 ? void 0 : _b.resolve();
            this.state = NativeAppState.DISCONNECTED;
            (_d = (_c = this.pending) === null || _c === void 0 ? void 0 : _c.reject) === null || _d === void 0 ? void 0 : _d.call(_c, new UnknownError("native application closed the connection before a response"));
            this.pending = null;
        }
        disconnectForcefully() {
            var _a, _b, _c;
            this.state = NativeAppState.DISCONNECTED;
            (_b = (_a = this.pending) === null || _a === void 0 ? void 0 : _a.reject) === null || _b === void 0 ? void 0 : _b.call(_a, new UnknownError("extension closed connection to native app prematurely"));
            this.pending = null;
            (_c = this.port) === null || _c === void 0 ? void 0 : _c.disconnect();
        }
        close() {
            if (this.state == NativeAppState.DISCONNECTED)
                return;
            this.disconnectForcefully();
        }
        send(message) {
            switch (this.state) {
                case NativeAppState.CONNECTED: {
                    return new Promise((resolve, reject) => {
                        var _a, _b;
                        this.pending = { resolve, reject };
                        const onResponse = async (message) => {
                            var _a;
                            (_a = this.port) === null || _a === void 0 ? void 0 : _a.onMessage.removeListener(onResponse);
                            try {
                                await Promise.race([
                                    this.activeConnection,
                                    throwAfterTimeout(config.NATIVE_GRACEFUL_DISCONNECT_TIMEOUT, new Error("Native application did not disconnect after response")),
                                ]);
                            }
                            catch (error) {
                                console.error(error);
                                this.disconnectForcefully();
                            }
                            finally {
                                const error = message === null || message === void 0 ? void 0 : message.error;
                                if (error) {
                                    reject(deserializeError(error));
                                }
                                else {
                                    resolve(message);
                                }
                                this.pending = null;
                            }
                        };
                        (_a = this.port) === null || _a === void 0 ? void 0 : _a.onMessage.addListener(onResponse);
                        config.DEBUG && console.log("Sending message to native app", JSON.stringify(message));
                        const messageSize = calculateJsonSize(message);
                        if (messageSize > config.NATIVE_MESSAGE_MAX_BYTES) {
                            throw new Error(`native application message exceeded ${config.NATIVE_MESSAGE_MAX_BYTES} bytes`);
                        }
                        (_b = this.port) === null || _b === void 0 ? void 0 : _b.postMessage(message);
                    });
                }
                case NativeAppState.UNINITIALIZED: {
                    return Promise.reject(new Error("unable to send message, native application port is not initialized yet"));
                }
                case NativeAppState.CONNECTING: {
                    return Promise.reject(new Error("unable to send message, native application port is still connecting"));
                }
                case NativeAppState.DISCONNECTED: {
                    return Promise.reject(new Error("unable to send message, native application port is disconnected"));
                }
                default: {
                    return Promise.reject(new Error("unable to send message, unexpected native app state"));
                }
            }
        }
        nextMessage(timeout) {
            return new Promise((resolve, reject) => {
                let cleanup = null;
                let timer = null;
                const onMessageListener = (message) => {
                    cleanup === null || cleanup === void 0 ? void 0 : cleanup();
                    if (message.error) {
                        reject(deserializeError(message.error));
                    }
                    else {
                        resolve(message);
                    }
                };
                const onDisconnectListener = () => {
                    cleanup === null || cleanup === void 0 ? void 0 : cleanup();
                    reject(new NativeUnavailableError("a message from native application was expected, but native application closed connection"));
                };
                cleanup = () => {
                    var _a, _b;
                    (_a = this.port) === null || _a === void 0 ? void 0 : _a.onDisconnect.removeListener(onDisconnectListener);
                    (_b = this.port) === null || _b === void 0 ? void 0 : _b.onMessage.removeListener(onMessageListener);
                    if (timer)
                        clearTimeout(timer);
                };
                timer = setTimeout(() => {
                    cleanup === null || cleanup === void 0 ? void 0 : cleanup();
                    reject(new NativeUnavailableError(`a message from native application was expected, but message wasn't received in ${timeout}ms`));
                }, timeout);
                if (!this.port) {
                    return reject(new NativeUnavailableError("missing native application port"));
                }
                this.port.onDisconnect.addListener(onDisconnectListener);
                this.port.onMessage.addListener(onMessageListener);
            });
        }
    }

    /**
     * Helper function to compose a token signing response message
     *
     * @param result Token signing result from the native application
     * @param nonce  The nonce related to the action
     * @param optional Optional message fields to be included in the response
     *
     * @returns A token signing response object
     */
    function tokenSigningResponse(result, nonce, optional) {
        const response = {
            nonce,
            result,
            src: "background.js",
            extension: config.VERSION,
            isWebeid: true,
            ...(optional ? optional : {}),
        };
        return response;
    }

    function errorToResponse(nonce, error) {
        if (error.code === ErrorCode$1.ERR_WEBEID_USER_CANCELLED) {
            return tokenSigningResponse("user_cancel", nonce);
        }
        else if (error.code === ErrorCode$1.ERR_WEBEID_NATIVE_FATAL ||
            error.code === ErrorCode$1.ERR_WEBEID_NATIVE_INVALID_ARGUMENT) {
            const nativeException = serializeError(error);
            return tokenSigningResponse("driver_error", nonce, { nativeException });
        }
        else {
            return tokenSigningResponse("technical_error", nonce, { error });
        }
    }

    /**
     * Map of ISO 639-2 three-letter language codes to ISO 639-1 two-letter language codes.
     *
     * This is only a partial list used for backwards compatibility.
     *
     * @see https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
     */
    var threeLetterLanguageCodes = {
        "est": "et",
        "eng": "en",
        "rus": "ru",
        "lit": "lt",
        "lat": "lv",
        "tur": "tr",
        "ces": "cs",
        "slk": "sk",
    };

    async function getCertificate(nonce, sourceUrl, lang, filter = "SIGN") {
        if (lang && Object.keys(threeLetterLanguageCodes).includes(lang)) {
            lang = threeLetterLanguageCodes[lang];
        }
        const nativeAppService = new NativeAppService();
        if (filter !== "SIGN") {
            const { message, name, stack } = new Error("Web-eID only allows signing with a signing certificate");
            return tokenSigningResponse("not_allowed", nonce, {
                message,
                name,
                stack,
            });
        }
        try {
            const nativeAppStatus = await nativeAppService.connect();
            config.DEBUG && console.log("Get certificate: connected to native", nativeAppStatus);
            const message = {
                command: "get-signing-certificate",
                arguments: {
                    origin: (new URL(sourceUrl)).origin,
                    ...(lang ? { lang } : {}),
                },
            };
            const response = await Promise.race([
                nativeAppService.send(message),
                throwAfterTimeout(config.TOKEN_SIGNING_USER_INTERACTION_TIMEOUT, new UserTimeoutError()),
            ]);
            if (!(response === null || response === void 0 ? void 0 : response.certificate)) {
                return tokenSigningResponse("no_certificates", nonce);
            }
            else {
                return tokenSigningResponse("ok", nonce, {
                    cert: new ByteArray().fromBase64(response.certificate).toHex(),
                });
            }
        }
        catch (error) {
            console.error(error);
            return errorToResponse(nonce, error);
        }
        finally {
            nativeAppService.close();
        }
    }

    const digestCommandToHashFunction = {
        "sha224": "SHA-224",
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
        "sha3-224": "SHA3-224",
        "sha3-256": "SHA3-256",
        "sha3-384": "SHA3-384",
        "sha3-512": "SHA3-512",
    };
    const hashFunctionToLength = {
        "SHA-224": 28,
        "SHA-256": 32,
        "SHA-384": 48,
        "SHA-512": 64,
        "SHA3-224": 28,
        "SHA3-256": 32,
        "SHA3-384": 48,
        "SHA3-512": 64,
    };
    async function sign(nonce, sourceUrl, certificate, hash, algorithm, lang) {
        if (lang && Object.keys(threeLetterLanguageCodes).includes(lang)) {
            lang = threeLetterLanguageCodes[lang];
        }
        const nativeAppService = new NativeAppService();
        try {
            const warnings = [];
            const nativeAppStatus = await nativeAppService.connect();
            config.DEBUG && console.log("Sign: connected to native", nativeAppStatus);
            let hashFunction = (Object.keys(digestCommandToHashFunction).includes(algorithm)
                ? digestCommandToHashFunction[algorithm]
                : algorithm);
            const expectedHashByteLength = (Object.keys(hashFunctionToLength).includes(hashFunction)
                ? hashFunctionToLength[hashFunction]
                : undefined);
            const hashByteArray = new ByteArray().fromHex(hash);
            if (hashByteArray.length !== expectedHashByteLength) {
                warnings.push(`${algorithm} hash must be ${expectedHashByteLength} bytes long.\n` +
                    `The provided hash was ${hashByteArray.length} bytes long.\n` +
                    "See further details at https://github.com/web-eid/web-eid-webextension#hwcrypto-compatibility");
                const autodetectedHashFunction = Object.keys(hashFunctionToLength).find((hashFunctionName) => (hashFunctionToLength[hashFunctionName] == hashByteArray.length));
                if (autodetectedHashFunction) {
                    warnings.push(`Changed the algorithm from ${hashFunction} to ${autodetectedHashFunction} in order to match the hash length`);
                    hashFunction = autodetectedHashFunction;
                }
            }
            const message = {
                command: "sign",
                arguments: {
                    hashFunction,
                    hash: hashByteArray.toBase64(),
                    origin: (new URL(sourceUrl)).origin,
                    certificate: new ByteArray().fromHex(certificate).toBase64(),
                    ...(lang ? { lang } : {}),
                },
            };
            const response = await Promise.race([
                nativeAppService.send(message),
                throwAfterTimeout(config.TOKEN_SIGNING_USER_INTERACTION_TIMEOUT, new UserTimeoutError()),
            ]);
            if (!(response === null || response === void 0 ? void 0 : response.signature)) {
                return tokenSigningResponse("technical_error", nonce);
            }
            else {
                return tokenSigningResponse("ok", nonce, {
                    signature: new ByteArray().fromBase64(response.signature).toHex(),
                    warnings,
                });
            }
        }
        catch (error) {
            console.error(error);
            return errorToResponse(nonce, error);
        }
        finally {
            nativeAppService.close();
        }
    }

    async function status$1(nonce) {
        const nativeAppService = new NativeAppService();
        try {
            const nativeAppStatus = await nativeAppService.connect();
            const version = nativeAppStatus.version.replace("+", ".");
            if (!version) {
                throw new Error("missing native application version");
            }
            const message = {
                command: "quit",
                arguments: {},
            };
            await nativeAppService.send(message);
            return tokenSigningResponse("ok", nonce, { version });
        }
        catch (error) {
            console.error(error);
            return errorToResponse(nonce, error);
        }
        finally {
            nativeAppService.close();
        }
    }

    var TokenSigningAction = {
        status: status$1,
        getCertificate,
        sign,
    };

    class MissingParameterError extends Error {
        constructor(message) {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_MISSING_PARAMETER;
        }
    }

    /**
     * Returns the URL where the PostMessage API's message originated
     *
     * @param sender PostMessage API's message sender
     * @returns
     */
    function getSenderUrl(sender) {
        if (!sender.url) {
            throw new UnknownError("missing sender url");
        }
        return sender.url;
    }

    var nativeAppConn;
    var emrtdTokenReady;
    async function authenticate(challengeNonce, photo, sender, libraryVersion, userInteractionTimeout, lang) {
        let nativeAppService;
        try {
            const decodedString = atob(challengeNonce);
            if (decodedString.length < 32) {
                throw new MissingParameterError("Base64-encoded cryptographic nonce with at least 256 bits of entropy is missing");
            }
            nativeAppService = new NativeAppService();
            nativeAppConn = nativeAppService;
            const nativeAppStatus = await nativeAppService.connect();
            config.DEBUG && console.log("Authenticate with EMRTD: connected to native", nativeAppStatus);
            const message = {
                command: "authenticate",
                arguments: {
                    challengeNonce,
                    photo,
                    origin: (new URL(getSenderUrl(sender))).origin,
                    ...(lang ? { lang } : {}),
                    userInteractionTimeout,
                },
            };
            const response = await Promise.race([
                nativeAppService.send(message),
                throwAfterTimeout(userInteractionTimeout, new UserTimeoutError()),
            ]);
            config.DEBUG && console.log("Authenticate with EMRTD: authentication token received");
            const isResponseValid = ((response === null || response === void 0 ? void 0 : response.EF_DG15) &&
                (response === null || response === void 0 ? void 0 : response.EF_DG1) &&
                (response === null || response === void 0 ? void 0 : response.EF_SOD) &&
                (response === null || response === void 0 ? void 0 : response.signature) &&
                (response === null || response === void 0 ? void 0 : response.format) &&
                (response === null || response === void 0 ? void 0 : response.appVersion));
            console.log("native app response:", response);
            if (isResponseValid) {
                emrtdTokenReady = new Date();
                return { action: Action$1.AUTHENTICATE_WITH_EMRTD_SUCCESS, ...response };
            }
            else {
                console.log("bad response will throw an exception");
                throw new UnknownError("unexpected response from native application");
            }
        }
        catch (error) {
            console.error("Authenticate with EMRTD:", error);
            if (error.message === 'String contains an invalid character') {
                let characterError = new MissingParameterError("Cryptographic nonce includes non UTF-8 characters or does not properly Base64 encoded");
                return {
                    action: Action$1.AUTHENTICATE_WITH_EMRTD_FAILURE,
                    error: serializeError(characterError),
                };
            }
            return {
                action: Action$1.AUTHENTICATE_WITH_EMRTD_FAILURE,
                error: serializeError(error),
            };
        }
        finally {
        }
    }

    async function authenticate_ca(eph_pubkey, capdu, signature, sender, userInteractionTimeout) {
        let currentDate = new Date();
        if ((currentDate.getTime() - emrtdTokenReady.getTime()) > 5000) {
            throw new UnknownError("The call was made in more than 5 seconds after webemrtd.authenticate() returned a successful response.");
        }
        let nativeAppService;
        try {
            nativeAppService = nativeAppConn;
            const nativeAppStatus = nativeAppService.state;
            config.DEBUG && console.log("Authenticate EMRTD CA: connected to native", nativeAppStatus);
            const message = {
                command: "authenticate_ca",
                arguments: {
                    eph_pubkey,
                    capdu,
                    origin: (new URL(getSenderUrl(sender))).origin,
                    signature,
                    userInteractionTimeout
                },
            };
            const response = await Promise.race([
                nativeAppService.send(message),
                throwAfterTimeout(userInteractionTimeout, new UserTimeoutError()),
            ]);
            config.DEBUG && console.log("Authenticate EMRTD CA: token received");
            const isResponseValid = ((response === null || response === void 0 ? void 0 : response.rapdu) &&
                (response === null || response === void 0 ? void 0 : response.duration));
            console.log("native app response:", response);
            if (isResponseValid) {
                return { action: Action$1.AUTHENTICATE_EMRTD_CA_SUCCESS, ...response };
            }
            else {
                console.log("bad response will throw an exception");
                throw new UnknownError("unexpected response from native application");
            }
        }
        catch (error) {
            console.error("Authenticate EMRTD CA:", error);
            return {
                action: Action$1.AUTHENTICATE_EMRTD_CA_FAILURE,
                error: serializeError(error),
            };
        }
        finally {
            nativeAppService === null || nativeAppService === void 0 ? void 0 : nativeAppService.close();
        }
    }

    const semverPattern = new RegExp("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)" +
        "(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$");
    var IdentifierDiff;
    (function (IdentifierDiff) {
        IdentifierDiff[IdentifierDiff["NEWER"] = 1] = "NEWER";
        IdentifierDiff[IdentifierDiff["SAME"] = 0] = "SAME";
        IdentifierDiff[IdentifierDiff["OLDER"] = -1] = "OLDER";
    })(IdentifierDiff || (IdentifierDiff = {}));
    function parseSemver(string = "") {
        const result = string.match(semverPattern);
        const [, majorStr, minorStr, patchStr, rc, build] = result ? result : [];
        const major = parseInt(majorStr, 10);
        const minor = parseInt(minorStr, 10);
        const patch = parseInt(patchStr, 10);
        for (const indentifier of [major, minor, patch]) {
            if (Number.isNaN(indentifier)) {
                throw new VersionInvalidError(`Invalid SemVer string '${string}'`);
            }
        }
        return { major, minor, patch, rc, build, string };
    }
    /**
     * Compares two Semver objects.
     *
     * @param {Semver} a First SemVer object
     * @param {Semver} b Second Semver object
     *
     * @returns {SemverDiff} Diff for major, minor and patch.
     */
    function compareSemver(a, b) {
        return {
            major: Math.sign(a.major - b.major),
            minor: Math.sign(a.minor - b.minor),
            patch: Math.sign(a.patch - b.patch),
        };
    }

    /**
     * Checks if update is required.
     *
     * @param status Object containing SemVer version strings for library, extension and native app.
     *
     * @returns Object which specifies if the extension or native app should be updated.
     */
    function checkCompatibility(versions) {
        const [librarySemver, extensionSemver, nativeAppSemver,] = [
            parseSemver(versions.library),
            parseSemver(versions.extension),
            parseSemver(versions.nativeApp),
        ];
        return {
            extension: (compareSemver(extensionSemver, librarySemver).major === IdentifierDiff.OLDER),
            nativeApp: (compareSemver(nativeAppSemver, librarySemver).major === IdentifierDiff.OLDER ||
                compareSemver(nativeAppSemver, extensionSemver).major === IdentifierDiff.OLDER),
        };
    }

    async function status(libraryVersion) {
        const extensionVersion = config.VERSION;
        const nativeAppService = new NativeAppService();
        try {
            const status = await nativeAppService.connect();
            const nativeApp = (status.version.startsWith("v")
                ? status.version.substring(1)
                : status.version);
            await nativeAppService.send({
                command: "quit",
                arguments: {},
            });
            const componentVersions = {
                library: libraryVersion,
                extension: extensionVersion,
                nativeApp,
            };
            const requiresUpdate = checkCompatibility(componentVersions);
            if (requiresUpdate.extension || requiresUpdate.nativeApp) {
                throw new VersionMismatchError(undefined, componentVersions, requiresUpdate);
            }
            return {
                action: Action$1.STATUS_SUCCESS,
                ...componentVersions,
            };
        }
        catch (error) {
            error.extension = extensionVersion;
            console.error("Status:", error);
            return {
                action: Action$1.STATUS_FAILURE,
                error: serializeError(error),
            };
        }
        finally {
            nativeAppService.close();
        }
    }

    async function onAction(message, sender) {
        var _a, _b, _c;
        switch (message.action) {
            case Action$1.AUTHENTICATE_WITH_EMRTD:
                return await authenticate(message.challengeNonce, message.photo, sender, message.libraryVersion, ((_a = message.options) === null || _a === void 0 ? void 0 : _a.userInteractionTimeout) || libraryConfig.DEFAULT_USER_INTERACTION_TIMEOUT, (_b = message.options) === null || _b === void 0 ? void 0 : _b.lang);
            case Action$1.AUTHENTICATE_EMRTD_CA:
                return await authenticate_ca(message.eph_pubkey, message.capdu, message.signature, sender, ((_c = message.options) === null || _c === void 0 ? void 0 : _c.userInteractionTimeout) || libraryConfig.DEFAULT_USER_INTERACTION_TIMEOUT);
            case Action$1.STATUS:
                return await status(message.libraryVersion);
        }
    }
    async function onTokenSigningAction(message, sender) {
        if (!sender.url)
            return;
        switch (message.type) {
            case "VERSION": {
                return await TokenSigningAction.status(message.nonce);
            }
            case "CERT": {
                return await TokenSigningAction.getCertificate(message.nonce, sender.url, message.lang, message.filter);
            }
            case "SIGN": {
                return await TokenSigningAction.sign(message.nonce, sender.url, message.cert, message.hash, message.hashtype, message.lang);
            }
        }
    }
    browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
        console.log("[debug] message: ", message);
        console.log("[debug] sender: ", sender);
        console.log("[debug] sendResponse: ", sendResponse);
        if (message.action) {
            onAction(message, sender).then(sendResponse);
        }
        else if (message.type) {
            onTokenSigningAction(message, sender).then(sendResponse);
        }
        return true;
    });
    async function showConsent() {
        const url = browser.runtime.getURL("views/installed.html");
        return await browser.tabs.create({ url, active: true });
    }
    browser.runtime.onInstalled.addListener(async ({ reason, temporary }) => {
        if (temporary)
            return;
        if (reason == "install") {
            await showConsent();
        }
    });

})();
//# sourceMappingURL=background.js.map
