/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { addMessagePreEditListener, addMessagePreSendListener, removeMessagePreEditListener, removeMessagePreSendListener } from "@api/MessageEvents";
import { updateMessage } from "@api/MessageUpdater";
import { Logger } from "@utils/Logger";
import definePlugin from "@utils/types";
import { Message } from "@vencord/discord-types";
const regexStartEnd = /START\|([a-zA-Z0-9+/]*?={0,3})\|END/;

const IV_LEN = 16;
const CHECKSUM_LEN = 8; // Ought to be enuf
const AES_BLOCKSIZE = 16;
const password = crypto.getRandomValues(new Uint8Array(32));
let binary = "";
password.forEach(element => binary += String.fromCharCode(element));
console.log("Your password is: " + btoa(binary));

/*
 * |=============================================================================================|
 * |IMPORTANT - THIS CODE IS DOGSHIT AND NEEDS MAJOR REFACTORING DONT COME AFTER ME BECAUSE OF IT|
 * |=============================================================================================|
*/


const LOGGER = new Logger("EncryptedChat", "#ff9900");

async function encrypt(text: string, password: Uint8Array<ArrayBuffer>) {
    const messageBytes = new TextEncoder().encode(text);
    const key = await crypto.subtle.importKey(
        "raw",
        password,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );
    const iv = await crypto.getRandomValues(new Uint8Array(IV_LEN));

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        messageBytes
    );

    return { encrypted: encrypted, iv: iv };
}

async function hash(bytes: Uint8Array<ArrayBuffer>) {
    return new Uint8Array(await crypto.subtle.digest({ name: "SHA-256" }, bytes));
}

const standardKey = "Trans4tw";

async function getStandardKey(channel_id: string) {
    // Channel id to be used later
    return await hash(new TextEncoder().encode(standardKey));
}

async function decrypt(messageBytes: Uint8Array<ArrayBuffer>, password: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
    const key = await crypto.subtle.importKey(
        "raw",
        password,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        messageBytes
    );
    return new Uint8Array(decrypted);
}

function concatArrayBuffers(...buffers: Uint8Array[]): Uint8Array {
    const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
    const result = new Uint8Array(totalLength);

    let offset = 0;
    for (const buffer of buffers) {
        result.set(buffer, offset);
        offset += buffer.byteLength;
    }

    return result;
}

async function createChecksum(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
    return (await hash(bytes)).slice(0, CHECKSUM_LEN);
}

async function messageEncrypt(inText: string, channel_id: string): Promise<string> {
    const textBytes = new TextEncoder().encode(inText);
    const checksum = await createChecksum(textBytes);
    LOGGER.log(`Plain bytes: ${textBytes}`);
    LOGGER.log(`Encrypt checksum: ${checksum}`);
    const { encrypted, iv } = await encrypt(inText, await getStandardKey(channel_id));
    const messageBytes = concatArrayBuffers(iv, checksum, new Uint8Array(encrypted));
    return `START|${toBase64(messageBytes)}|END`;
}

function uint8ArraysEqual(a, b) {
    if (a === b) return true; // same reference
    if (a.length !== b.length) return false;

    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }

    return true;
}

async function tryMessageDecrypt(bytes: Uint8Array<ArrayBuffer>, channel_id: string): Promise<undefined | string> {
    if ((bytes.byteLength - IV_LEN - CHECKSUM_LEN) % AES_BLOCKSIZE !== 0) {
        // This can't be a valid payload since the sizes are wrong
        LOGGER.warn(`Message has valid Start End encoding, yet payload size (${bytes.byteLength - IV_LEN - CHECKSUM_LEN}) is wrong (Should be a multiple of ${AES_BLOCKSIZE}).`);
        // return;
    }
    const iv = bytes.slice(0, IV_LEN);
    LOGGER.log("Decrypt IVS: ", iv);
    const messageChecksum = bytes.slice(IV_LEN, IV_LEN + CHECKSUM_LEN);
    LOGGER.log("Decrypt checksum: ", messageChecksum);

    const encrypted = bytes.slice(IV_LEN + CHECKSUM_LEN, bytes.byteLength);
    LOGGER.log("Encrypted Bytes: ", encrypted);

    const decrypted = await decrypt(encrypted, await getStandardKey(channel_id), iv);
    LOGGER.log("Decrypted ", decrypted);

    const checksum = await createChecksum(decrypted);

    if (!uint8ArraysEqual(messageChecksum, checksum)) {
        LOGGER.warn("Message decryption was successful but checksums don't match. Your password is most likely wrong.");
        return;
    }
    let text;
    try {
        text = new TextDecoder().decode(decrypted);
    } catch {
        LOGGER.warn("Decrypted checksums match, yet encoding threw an exception. This is probably a malicious text injection or smt smt.");

        // Probably something fishy going on
        return;
    }

    return text;
}

// Optimally we'd be doing this using discords delegate system, but eh

function toBase64(bytes: Uint8Array) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}


function handleIncomingMessage(message: Message) {
    const matches = regexStartEnd.exec(message.content);
    if (!matches) {
        LOGGER.info(`Incoming message (${message.content}) didn't match with the regex`);
        return;
    }
    const base64 = matches[1];
    LOGGER.info(`Extracted base64 part: '${base64}'`);
    let bytes;
    try {
        const binaryString = atob(base64);
        bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0));
    } catch {
        LOGGER.error("Extracted part wasn't valid base 64 (which should be impossible)");
        return;
    }

    tryMessageDecrypt(bytes, message.channel_id).then(function (decrypted: string | undefined) {
        if (!decrypted) {
            // This message probably wasn't encrypted to begin with
            return;
        }
        // This might be run even before the message has first rendered, is that bad? who knoes
        updateMessage(message.channel_id, message.id, { content: decrypted });
    });

    return message.content;
}


export default definePlugin({
    name: "EncryptedChat",
    description: "A plugin to let you communicate with symmetric encryption in servers (TODO: asymmetric for DMS)",
    authors: [{ name: "Leah", id: 429195069015195650n }, { name: "Fern", id: 972889822857420810n }],

    handleIncomingMessage,

    patches: [
        {
            find: "!1,hideSimpleEmbedContent",
            replacement: {
                match: /(let{toAST:.{0,125}?)\(\i\?\?\i\).content/,
                replace: "const textReplaceContent=$self.handleIncomingMessage(arguments[2]?.contentMessage??arguments[1]);$&"
            }
        }
    ],

    start() {
        this.onSent = addMessagePreSendListener(async (channelId, messageObj, extra) => {
            messageObj.content = await messageEncrypt(messageObj.content, channelId);
            return { cancel: false };
        });

        this.onEdit = addMessagePreEditListener(async (channelId, messageId, messageObj) => {
            messageObj.content = await messageEncrypt(messageObj.content, channelId);
            return { cancel: false };
        });
    },
    stop() {
        removeMessagePreSendListener(this.onSent);
        removeMessagePreEditListener(this.onEdit);
    }
});
