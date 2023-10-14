const fs = require("fs");
const FormData = require("form-data");
const axios = require("axios");

async function upload(path) {
    const server = await getServer();
    const link = await uploadFile(path, server);
    return link
}

async function getServer() {
    const res = await axios({
        url: `https://api.gofile.io/getServer`,
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
    formData.append('file', fs.createReadStream(path))

    const res = await axios({
        url: `https://${server}.gofile.io/uploadFile`,
        method: "POST",
        headers: {
            accept: "*/*",
            "accept-language": "en-US,en;",
            "cache-control": "no-cache",
            pragma: "no-cache",
            referrer: "https://gofile.io/uploadFiles",
            mode: "cors",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/85.0.564.44",
            dnt: 1,
            origin: "https://gofile.io",
            ...formData.getHeaders(),
        },
        'maxContentLength': Infinity,
        'maxBodyLength': Infinity,
        referrer: "https://gofile.io/uploadFiles",
        data: formData,
    });

    if (res.data.status !== "ok") {
        throw new Error(`Uploading file failed: ${JSON.stringify(res.data)}`);
    }

    return res.data.data.downloadPage;
}


module.exports = {
    upload
}
